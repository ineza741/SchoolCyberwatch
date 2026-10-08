package com.schoolcyberwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for the OpenSearch query JSON built by WazuhIndexerClient.
 * Verifies rule/date/agent filters and aggregation structure without a
 * live Wazuh indexer (representative data only - not integration proof).
 */
class WazuhIndexerClientQueryTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    @DisplayName("Rule filter builds a terms clause on rule.id with every id")
    void ruleFilterBuildsTermsClause() throws Exception {
        JsonNode query = WazuhIndexerClient.queryNode("60122,100200,550", null, null, null);
        JsonNode terms = query.path("bool").path("filter").get(0).path("terms").path("rule.id");
        assertTrue(terms.isArray());
        assertEquals(3, terms.size());
        assertEquals("60122", terms.get(0).asText());
        assertEquals("100200", terms.get(1).asText());
        assertEquals("550", terms.get(2).asText());
    }

    @Test
    @DisplayName("Blank rule filter produces no rule clause (searches all rules)")
    void blankRuleFilterOmitsClause() throws Exception {
        JsonNode query = WazuhIndexerClient.queryNode(null, null, null, null);
        JsonNode filter = query.path("bool").path("filter");
        assertFalse(filter.iterator().hasNext(), "filter must be empty when nothing is given");
    }

    @Test
    @DisplayName("since/until build a timestamp range filter")
    void dateRangeClause() throws Exception {
        JsonNode query = WazuhIndexerClient.queryNode("60122",
                "2026-09-01T00:00:00Z", "2026-09-15T23:59:59Z", null);
        // The rule terms clause is filter[0]; find the range clause by shape.
        JsonNode range = null;
        for (JsonNode clause : query.path("bool").path("filter")) {
            if (clause.has("range")) {
                range = clause.path("range").path("timestamp");
            }
        }
        assertEquals("2026-09-01T00:00:00Z", range.path("gt").asText());
        assertEquals("2026-09-15T23:59:59Z", range.path("lte").asText());
    }

    @Test
    @DisplayName("Agent filter builds a term clause on agent.id")
    void agentFilterClause() throws Exception {
        JsonNode query = WazuhIndexerClient.queryNode(null, null, null, "001");
        JsonNode term = query.path("bool").path("filter").get(0).path("term");
        assertEquals("001", term.path("agent.id").asText());
    }

    @Test
    @DisplayName("Alert query sorts by timestamp descending and caps the size")
    void alertQuerySortAndSize() throws Exception {
        JsonNode root = json.readTree(
                WazuhIndexerClient.alertQuery("60122", null, null, null, 50));
        assertEquals(50, root.path("size").asInt());
        assertEquals("desc", root.path("sort").get(0).path("timestamp").path("order").asText());
        assertTrue(root.path("query").isObject());
    }

    @Test
    @DisplayName("Count query requests zero rows and carries the query only")
    void countQueryShape() throws Exception {
        JsonNode root = json.readTree(
                WazuhIndexerClient.countQuery("60122", null, null, null, null));
        assertEquals(0, root.path("size").asInt());
        assertTrue(root.path("track_total_hits").asBoolean());
        assertTrue(root.path("query").isObject());
        assertFalse(root.has("aggs"));
    }

    @Test
    @DisplayName("Count query with an aggregation adds a terms agg on the field")
    void countQueryWithAggregation() throws Exception {
        JsonNode root = json.readTree(
                WazuhIndexerClient.countQuery("60122,100200", null, null, null, "rule.id"));
        assertEquals("rule.id",
                root.path("aggs").path("by_field").path("terms").path("field").asText());
        assertEquals(0, root.path("size").asInt());
    }

    @Test
    @DisplayName("Aggregation buckets are read into a rule -> count map")
    void aggregationBucketsToMap() throws Exception {
        // Simulated indexer response - aggregations sit at the root beside
        // hits, exactly like a real OpenSearch terms aggregation.
        String response = """
            {"hits":{"total":{"value":3}},
              "aggregations":{"by_field":{"buckets":[
                {"key":"60122","doc_count":2},
                {"key":"100200","doc_count":1}]}}}
            """;
        Map<String, Long> counts =
                WazuhIndexerClient.readTermsAggregation(json.readTree(response));
        assertEquals(2L, counts.get("60122"));
        assertEquals(1L, counts.get("100200"));
        assertEquals(2, counts.size());
    }

    @Test
    @DisplayName("Alert hits are extracted from the OpenSearch response envelope")
    void extractsHitsFromEnvelope() throws Exception {
        String response = """
            {"hits":{"total":{"value":1},"hits":[
              {"_index":"wazuh-alerts-4.x-2026.09","_id":"abc","_source":{
                 "id":"alert-77","timestamp":"2026-09-15T15:09:58.576+0000",
                 "agent":{"id":"001","name":"WIN-HUR37I74T1G"},
                 "rule":{"id":60122,"level":5,"description":"Windows logon failure."}}}]}}
            """;
        JsonNode root = json.readTree(response);
        List<JsonNode> sources = WazuhIndexerClient.extractAlerts(root);
        assertEquals(1, sources.size());
        assertEquals("60122", sources.get(0).path("rule").path("id").asText());
    }

    @Test
    @DisplayName("Document lookup uses an ids query across wazuh-alerts-* indices")
    void idsQueryBuildsByDocumentId() throws Exception {
        JsonNode root = json.readTree(WazuhIndexerClient.idQuery("abc123"));
        assertEquals(1, root.path("size").asInt());
        assertEquals("abc123", root.path("query").path("ids").path("values").get(0).asText());
    }

    @Test
    @DisplayName("Daily count query aggregates monitored alerts by local calendar day")
    void dailyCountQueryShape() throws Exception {
        JsonNode root = json.readTree(WazuhIndexerClient.dailyCountQuery("60122,100200",
                "2026-09-01T00:00:00Z", "2026-09-30T23:59:59Z"));
        JsonNode histogram = root.path("aggs").path("by_day").path("date_histogram");
        assertEquals(0, root.path("size").asInt());
        assertEquals("timestamp", histogram.path("field").asText());
        assertEquals("day", histogram.path("calendar_interval").asText());
        assertEquals("yyyy-MM-dd", histogram.path("format").asText());
        assertEquals("60122", root.path("query").path("bool").path("filter")
                .get(0).path("terms").path("rule.id").get(0).asText());
    }

    @Test
    @DisplayName("Date histogram buckets are read as day to count entries")
    void readsDateHistogram() throws Exception {
        String response = """
            {"aggregations":{"by_day":{"buckets":[
              {"key_as_string":"2026-09-15","doc_count":7},
              {"key_as_string":"2026-09-16","doc_count":2}]}}}
            """;
        Map<String, Long> counts = WazuhIndexerClient.readDateHistogram(json.readTree(response));
        assertEquals(7L, counts.get("2026-09-15"));
        assertEquals(2L, counts.get("2026-09-16"));
    }
}
