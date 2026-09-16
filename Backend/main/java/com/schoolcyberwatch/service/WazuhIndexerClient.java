package com.schoolcyberwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.schoolcyberwatch.config.WazuhIndexerProperties;
import com.schoolcyberwatch.exception.WazuhUnavailableException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Low-level client for the Wazuh Indexer (OpenSearch, port 9200).
 *
 * In Wazuh 4.x the manager API does not serve alert data - alerts live in
 * the wazuh-alerts-* indices and are queried with the standard OpenSearch
 * _search API using HTTP Basic auth.
 *
 * - The indexer ships with a self-signed certificate, so TLS trust is
 *   relaxed for this prototype ONLY (isolated lab network).
 * - Every failure is surfaced as WazuhUnavailableException so callers and
 *   the frontend can degrade gracefully ("monitoring temporarily unavailable").
 */
@Service
public class WazuhIndexerClient {

    private static final Logger log = LoggerFactory.getLogger(WazuhIndexerClient.class);

    private final WazuhIndexerProperties properties;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public WazuhIndexerClient(WazuhIndexerProperties properties) {
        this.properties = properties;
        this.restTemplate = buildRestTemplate();
        trustAllCertificates();
    }

    private RestTemplate buildRestTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(properties.getTimeoutSeconds() * 1000);
        factory.setReadTimeout(properties.getTimeoutSeconds() * 1000);
        return new RestTemplate(factory);
    }

    /**
     * The Wazuh indexer ships with a self-signed TLS certificate. For this
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
            log.warn("Could not relax TLS verification for Wazuh indexer: {}", e.getMessage());
        }
    }

    /** True when the indexer is reachable and credentials work. */
    public boolean isAvailable() {
        try {
            search("wazuh-alerts-*", alertQuery(null, 1));
            return true;
        } catch (WazuhUnavailableException e) {
            return false;
        }
    }

    /**
     * Searches the wazuh-alerts-* indices. Returns the raw alert _source
     * objects (newest first), or an empty list when nothing matched.
     */
    public List<JsonNode> searchAlerts(String ruleFilter, String sinceIso, int limit) {
        JsonNode response = search("wazuh-alerts-*", alertQuery(ruleFilter, sinceIso, limit));
        List<JsonNode> alerts = new ArrayList<>();
        JsonNode hits = response.path("hits").path("hits");
        if (hits.isArray()) {
            for (JsonNode hit : hits) {
                JsonNode source = hit.path("_source");
                if (source.isObject()) {
                    alerts.add(source);
                }
            }
        }
        return alerts;
    }

    /** Total number of matching alerts (for count-style queries). */
    public long countAlerts(String ruleFilter, String sinceIso) {
        JsonNode response = search("wazuh-alerts-*", countQuery(ruleFilter, sinceIso));
        return response.path("hits").path("total").path("value").asLong(0);
    }

    // ------------------------------------------------------------------
    // query building + execution
    // ------------------------------------------------------------------

    private static String alertQuery(String ruleFilter, String sinceIso, int limit) {
        ObjectNode root = objectMapper().createObjectNode();
        root.put("size", Math.max(1, limit));
        root.set("query", queryNode(ruleFilter, sinceIso));
        ArrayNode sort = root.putArray("sort");
        ObjectNode sortSpec = sort.addObject();
        sortSpec.putObject("timestamp").put("order", "desc");
        return toJson(root);
    }

    private static String alertQuery(String ruleFilter, int limit) {
        return alertQuery(ruleFilter, null, limit);
    }

    private static String countQuery(String ruleFilter, String sinceIso) {
        ObjectNode root = objectMapper().createObjectNode();
        root.put("size", 0);
        root.set("query", queryNode(ruleFilter, sinceIso));
        return toJson(root);
    }

    /**
     * Builds the OpenSearch query: terms filter on rule.id (when given) and
     * a range filter on timestamp (when sinceIso is given).
     */
    private static ObjectNode queryNode(String ruleFilter, String sinceIso) {
        ObjectNode query = objectMapper().createObjectNode();
        ArrayNode must = query.putObject("bool").putArray("filter");
        if (ruleFilter != null && !ruleFilter.isBlank()) {
            ObjectNode terms = must.addObject();
            ArrayNode values = terms.putObject("terms").putArray("rule.id");
            for (String part : ruleFilter.split(",")) {
                String value = part.trim();
                if (!value.isEmpty()) {
                    values.add(value);
                }
            }
        }
        if (sinceIso != null && !sinceIso.isBlank()) {
            must.addObject().putObject("range").putObject("timestamp")
                    .put("gt", sinceIso)
                    .put("format", "strict_date_optional_time"); // accepts 2026-09-15T15:03:46Z
        }
        return query;
    }

    private JsonNode search(String index, String jsonBody) {
        String url = properties.getBaseUrl() + "/" + index + "/_search";

        String basic = Base64.getEncoder().encodeToString(
                (properties.getUsername() + ":" + properties.getPassword())
                        .getBytes(StandardCharsets.UTF_8));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Basic " + basic);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(jsonBody, headers), String.class);
            return objectMapper.readTree(response.getBody());
        } catch (ResourceAccessException e) {
            throw new WazuhUnavailableException(
                    "Wazuh indexer is unreachable at " + properties.getBaseUrl(), e);
        } catch (Exception e) {
            throw new WazuhUnavailableException(
                    "Wazuh indexer query failed: " + e.getMessage(), e);
        }
    }

    private static ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    private static String toJson(ObjectNode node) {
        try {
            return new ObjectMapper().writeValueAsString(node);
        } catch (Exception e) {
            throw new WazuhUnavailableException("Could not build indexer query.", e);
        }
    }
}
