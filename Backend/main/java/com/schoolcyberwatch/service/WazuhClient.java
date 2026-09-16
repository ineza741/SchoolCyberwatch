package com.schoolcyberwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.schoolcyberwatch.config.WazuhProperties;
import com.schoolcyberwatch.exception.WazuhUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Low-level client for the Wazuh Manager API (Wazuh 4.x, port 55000).
 *
 * - Authenticates with HTTP Basic credentials (user/password from env vars).
 * - The manager uses a self-signed certificate, so TLS trust is relaxed for
 *   this prototype ONLY (acceptable on an isolated lab network).
 * - Every failure is surfaced as WazuhUnavailableException so callers and the
 *   frontend can degrade gracefully ("monitoring temporarily unavailable").
 */
@Service
public class WazuhClient {

    private static final Logger log = LoggerFactory.getLogger(WazuhClient.class);

    private final WazuhProperties properties;
    private final RestTemplate restTemplate;

    /** Cached JWT from GET /security/user/authenticate and its expiry. */
    private volatile String cachedToken;
    private volatile Instant tokenExpiresAt = Instant.EPOCH;
    private final ReentrantLock tokenLock = new ReentrantLock();

    public WazuhClient(WazuhProperties properties) {
        this.properties = properties;
        this.restTemplate = buildRestTemplate();
    }

    private RestTemplate buildRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(properties.getTimeoutSeconds() * 1000);
        factory.setReadTimeout(properties.getTimeoutSeconds() * 1000);
        trustAllCertificates();
        return new RestTemplate(factory);
    }

    /**
     * The Wazuh manager ships with a self-signed TLS certificate. For this
     * university prototype on an isolated lab network we accept it. This must
     * never be done on a production, internet-facing system.
     */
    private static void trustAllCertificates() {
        try {
            TrustManager[] trustAll = new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            // Hostname verification is separate from trust validation in Java:
            // without this, the self-signed cert (no IP SAN for the lab host)
            // fails with "No subject alternative names matching IP address".
            HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
        } catch (Exception e) {
            log.warn("Could not relax TLS verification for Wazuh: {}", e.getMessage());
        }
    }

    /** True when the manager API is reachable and credentials work. */
    public boolean isAvailable() {
        try {
            authenticate();
            return true;
        } catch (WazuhUnavailableException e) {
            return false;
        }
    }

    /**
     * Returns a valid JWT. Authenticates lazily and caches the token until
     * roughly 60 seconds before its stated expiry.
     */
    public String authenticate() {
        tokenLock.lock();
        try {
            if (cachedToken != null && Instant.now().isBefore(tokenExpiresAt)) {
                return cachedToken;
            }

            if (isBlank(properties.getPassword())) {
                throw new WazuhUnavailableException(
                        "Wazuh API password is not configured (set WAZUH_API_PASSWORD).");
            }

            // Wazuh accepts Basic auth on the token endpoint and returns a JWT.
            String basic = Base64.getEncoder().encodeToString(
                    (properties.getUsername() + ":" + properties.getPassword())
                            .getBytes(StandardCharsets.UTF_8));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.set("Authorization", "Basic " + basic);

            ResponseEntity<String> response;
            try {
                response = restTemplate.exchange(
                        uri("/security/user/authenticate"),
                        HttpMethod.POST,
                        new HttpEntity<>(new LinkedMultiValueMap<>(), headers),
                        String.class);
            } catch (ResourceAccessException e) {
                throw new WazuhUnavailableException(
                        "Wazuh manager is unreachable at " + properties.getBaseUrl(), e);
            } catch (Exception e) {
                throw new WazuhUnavailableException(
                        "Wazuh authentication failed: " + e.getMessage(), e);
            }

            JsonNode body = parseJson(response.getBody());
            String token = body.path("data").path("token").asText(null);
            if (token == null || token.isBlank()) {
                throw new WazuhUnavailableException("Wazuh returned no token.");
            }

            // JWTs carry "exp" (seconds since epoch). Read it; default 15 min.
            long expiresAtSeconds = parseJwtExpiry(token);
            if (expiresAtSeconds <= 0) {
                expiresAtSeconds = Instant.now().getEpochSecond() + 15 * 60;
            }
            cachedToken = token;
            tokenExpiresAt = Instant.ofEpochSecond(expiresAtSeconds - 60);
            return token;
        } finally {
            tokenLock.unlock();
        }
    }

    /**
     * Performs an authenticated GET against the Wazuh API and returns the
     * parsed JSON body (the "data" node, as returned by the manager).
     */
    public JsonNode getData(String path, MultiValueMap<String, String> queryParams) {
        String token = authenticate();
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(properties.getBaseUrl() + path);
        if (queryParams != null) {
            builder.queryParams(queryParams);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + token);

        ResponseEntity<String> response;
        try {
            response = restTemplate.exchange(
                    builder.build().encode().toUri(),
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class);
        } catch (ResourceAccessException e) {
            cachedToken = null; // force re-auth next time
            throw new WazuhUnavailableException("Wazuh manager is unreachable at " + properties.getBaseUrl(), e);
        } catch (Exception e) {
            cachedToken = null;
            throw new WazuhUnavailableException("Wazuh API call failed for " + path + ": " + e.getMessage(), e);
        }

        JsonNode body = parseJson(response.getBody());
        return body.path("data");
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private URI uri(String path) {
        return URI.create(properties.getBaseUrl() + path);
    }

    private static JsonNode parseJson(String raw) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readTree(
                    raw == null ? "{}" : raw);
        } catch (Exception e) {
            throw new WazuhUnavailableException("Wazuh returned invalid JSON.", e);
        }
    }

    /** Extracts the "exp" claim from a JWT payload without verifying it. */
    private static long parseJwtExpiry(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                return -1;
            }
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            JsonNode claims = new com.fasterxml.jackson.databind.ObjectMapper().readTree(payload);
            return claims.path("exp").asLong(-1);
        } catch (Exception e) {
            return -1;
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
