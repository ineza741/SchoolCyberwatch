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
import org.springframework.web.client.HttpClientErrorException;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
            search("wazuh-alerts-*", alertQuery(null, null, 1));
            return true;
        } catch (WazuhUnavailableException e) {
            return false;
        }
    }

    /**
     * Searches the wazuh-alerts-* indices. Returns the raw alert _source
     * objects (newest first), or an empty list when nothing matched.
     *
     * @param ruleFilter comma-separated rule IDs (null/blank = any rule)
     * @param sinceIso   lower timestamp bound (exclusive, may be null)
     * @param untilIso   upper timestamp bound (inclusive, may be null)
     * @param agentId    optional Wazuh agent id filter (e.g. "001")
     * @param limit      maximum number of alerts to return
     */
    public List<JsonNode> searchAlerts(String ruleFilter, String sinceIso, String untilIso,
                                       String agentId, int limit) {
        JsonNode response = search("wazuh-alerts-*",
                alertQuery(ruleFilter, sinceIso, untilIso, agentId, limit));
        return extractAlerts(response);
    }

    /** Convenience overload used by existing callers (no until/agent filter). */
    public List<JsonNode> searchAlerts(String ruleFilter, String sinceIso, int limit) {
        return searchAlerts(ruleFilter, sinceIso, null, null, limit);
    }

    /** Fetches a single alert by its indexer document id, or null if absent. */
    public JsonNode fetchAlertById(String alertId) {
        JsonNode response = search("wazuh-alerts-*", idQuery(alertId));
        JsonNode hits = response.path("hits").path("hits");
        if (!hits.isArray() || hits.isEmpty()) {
            return null;
        }
        JsonNode hit = hits.get(0);
        JsonNode source = hit.path("_source");
        if (source.isObject()) {
            ObjectNode copy = (ObjectNode) source.deepCopy();
            String docId = hit.path("_id").asText(alertId);
            copy.put("_id", docId);
            return copy;
        }
        return source;
    }

    /** Total number of matching alerts (for count-style queries). */
    public long countAlerts(String ruleFilter, String sinceIso, String untilIso, String agentId) {
        JsonNode response = search("wazuh-alerts-*", countQuery(ruleFilter, sinceIso, untilIso, agentId));
        return response.path("hits").path("total").path("value").asLong(0);
    }

    /** Convenience overload used by existing callers. */
    public long countAlerts(String ruleFilter, String sinceIso) {
        return countAlerts(ruleFilter, sinceIso, null, null);
    }

    /**
     * Counts matching alerts grouped by rule.id. Returns a map of
     * ruleId (as string) -> count. Used by dashboard statistics.
     */
    public Map<String, Long> countAlertsByRule(String ruleFilter, String sinceIso, String untilIso) {
        JsonNode response = search("wazuh-alerts-*",
                countQuery(ruleFilter, sinceIso, untilIso, null, "rule.id"));
        return readTermsAggregation(response);
    }

    /**
     * Counts matching alerts grouped by rule.level. Returns a map of
     * level (as string) -> count. Used by dashboard statistics.
     */
    public Map<String, Long> countAlertsByLevel(String ruleFilter, String sinceIso, String untilIso) {
        JsonNode response = search("wazuh-alerts-*",
                countQuery(ruleFilter, sinceIso, untilIso, null, "rule.level"));
        return readTermsAggregation(response);
    }

    /**
     * Counts matching alerts grouped by agent.name. Returns a map of
     * agent name -> count, so callers can derive the number of distinct
     * endpoints from the key set. Uses a terms aggregation with size 0 -
     * alert rows are never downloaded to answer a count question.
     */
    public Map<String, Long> countAlertsByAgent(String ruleFilter, String sinceIso, String untilIso) {
        JsonNode response = search("wazuh-alerts-*",
                countQuery(ruleFilter, sinceIso, untilIso, null, "agent.name"));
        return readTermsAggregation(response);
    }

    /** Counts matching alerts per calendar day in the system time zone. */
    public Map<String, Long> countAlertsByDay(String ruleFilter, String sinceIso, String untilIso) {
        JsonNode response = search("wazuh-alerts-*", dailyCountQuery(ruleFilter, sinceIso, untilIso));
        return readDateHistogram(response);
    }

    // ------------------------------------------------------------------
    // query building + execution
    // ------------------------------------------------------------------

    static String alertQuery(String ruleFilter, String sinceIso, String untilIso,
                                     String agentId, int limit) {
        ObjectNode root = objectMapper().createObjectNode();
        root.put("size", Math.max(1, limit));
        root.set("query", queryNode(ruleFilter, sinceIso, untilIso, agentId));
        ArrayNode sort = root.putArray("sort");
        ObjectNode sortSpec = sort.addObject();
        sortSpec.putObject("timestamp").put("order", "desc");
        return toJson(root);
    }

    private static String alertQuery(String ruleFilter, String sinceIso, int limit) {
        return alertQuery(ruleFilter, sinceIso, null, null, limit);
    }

    private static String countQuery(String ruleFilter, String sinceIso, String untilIso, String agentId) {
        return countQuery(ruleFilter, sinceIso, untilIso, agentId, null);
    }

    static String countQuery(String ruleFilter, String sinceIso, String untilIso,
                                     String agentId, String aggregationField) {
        ObjectNode root = objectMapper().createObjectNode();
        root.put("size", 0);
        root.put("track_total_hits", true);
        root.set("query", queryNode(ruleFilter, sinceIso, untilIso, agentId));
        if (aggregationField != null) {
            root.putObject("aggs")
                    .putObject("by_field")
                    .putObject("terms")
                    .put("field", aggregationField)
                    .put("size", 50);
        }
        return toJson(root);
    }

    /** Finds a document by its Wazuh document id without relying on a wildcard _doc URL. */
    static String idQuery(String alertId) {
        ObjectNode root = objectMapper().createObjectNode();
        root.put("size", 1);
        ObjectNode ids = root.putObject("query").putObject("ids");
        ids.putArray("values").add(alertId);
        return toJson(root);
    }

    static String dailyCountQuery(String ruleFilter, String sinceIso, String untilIso) {
        ObjectNode root = objectMapper().createObjectNode();
        root.put("size", 0);
        root.set("query", queryNode(ruleFilter, sinceIso, untilIso, null));
        ObjectNode histogram = root.putObject("aggs")
                .putObject("by_day")
                .putObject("date_histogram");
        histogram.put("field", "timestamp");
        histogram.put("calendar_interval", "day");
        histogram.put("time_zone", java.time.ZoneId.systemDefault().getId());
        histogram.put("format", "yyyy-MM-dd");
        histogram.put("min_doc_count", 0);
        return toJson(root);
    }

    /**
     * Builds the OpenSearch query: terms filter on rule.id (when given) and
     * range filters on timestamp (when since/until are given) and agent.id
     * (when agentId is given).
     */
    static ObjectNode queryNode(String ruleFilter, String sinceIso, String untilIso,
                                        String agentId) {
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
        if ((sinceIso != null && !sinceIso.isBlank())
                || (untilIso != null && !untilIso.isBlank())) {
            ObjectNode range = must.addObject().putObject("range").putObject("timestamp");
            if (sinceIso != null && !sinceIso.isBlank()) {
                range.put("gt", sinceIso);
            }
            if (untilIso != null && !untilIso.isBlank()) {
                range.put("lte", untilIso);
            }
            range.put("format", "strict_date_optional_time"); // accepts 2026-09-15T15:03:46Z
        }
        if (agentId != null && !agentId.isBlank()) {
            must.addObject().putObject("term").put("agent.id", agentId.trim());
        }
        return query;
    }

    static List<JsonNode> extractAlerts(JsonNode response) {
        List<JsonNode> alerts = new ArrayList<>();
        JsonNode hits = response.path("hits").path("hits");
        if (hits.isArray()) {
            for (JsonNode hit : hits) {
                JsonNode source = hit.path("_source");
                if (source.isObject()) {
                    ObjectNode copy = (ObjectNode) source.deepCopy();
                    String docId = hit.path("_id").asText(null);
                    if (docId != null && !docId.isBlank()) {
                        copy.put("_id", docId);
                    }
                    alerts.add(copy);
                }
            }
        }
        return alerts;
    }

    static Map<String, Long> readTermsAggregation(JsonNode response) {
        Map<String, Long> counts = new LinkedHashMap<>();
        JsonNode buckets = response.path("aggregations").path("by_field").path("buckets");
        if (buckets.isArray()) {
            for (JsonNode bucket : buckets) {
                counts.put(bucket.path("key").asText(""), bucket.path("doc_count").asLong(0));
            }
        }
        return counts;
    }

    static Map<String, Long> readDateHistogram(JsonNode response) {
        Map<String, Long> counts = new LinkedHashMap<>();
        JsonNode buckets = response.path("aggregations").path("by_day").path("buckets");
        if (buckets.isArray()) {
            for (JsonNode bucket : buckets) {
                String day = bucket.path("key_as_string").asText(null);
                if (day == null || day.isBlank()) {
                    day = java.time.Instant.ofEpochMilli(bucket.path("key").asLong())
                            .atZone(java.time.ZoneId.systemDefault()).toLocalDate().toString();
                }
                counts.put(day, bucket.path("doc_count").asLong(0));
            }
        }
        return counts;
    }

    private HttpHeaders basicAuthHeaders() {
        String basic = Base64.getEncoder().encodeToString(
                (properties.getUsername() + ":" + properties.getPassword())
                        .getBytes(StandardCharsets.UTF_8));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Basic " + basic);
        return headers;
    }

    private JsonNode search(String index, String jsonBody) {
        String url = properties.getBaseUrl() + "/" + index + "/_search";
        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.POST, new HttpEntity<>(jsonBody, basicAuthHeaders()), String.class);
            return objectMapper.readTree(response.getBody());
        } catch (HttpClientErrorException.Unauthorized e) {
            throw new WazuhUnavailableException(
                    "Wazuh indexer rejected the credentials (check WAZUH_INDEXER_USERNAME / "
                            + "WAZUH_INDEXER_PASSWORD).", e);
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
