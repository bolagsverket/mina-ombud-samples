package se.minaombud.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.NumericNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RFC 8785.
 * <a href="https://www.rfc-editor.org/rfc/rfc8785.html">RFC 8785</a>
 */
public class JsonCanonicalizer {


    private final Set<String> excluded = new HashSet<>();
    private final JsonNode root;
    private ObjectMapper mapper = Json.DEFAULT_MAPPER;

    private JsonCanonicalizer(JsonNode root) {
        this.root = root;
    }

    private static JsonCanonicalizer root(JsonNode node) {
        return new JsonCanonicalizer(node);
    }

    /**
     * Skapa instans från JSON-sträng.
     * @param json JSON-sträng
     * @return JsonCanonicalizer
     */
    public static JsonCanonicalizer root(String json) {
        try {
            return new JsonCanonicalizer(Json.DEFAULT_MAPPER.readTree(json));
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON deserialization failed", e);
        }
    }

    /**
     * Skapa instans från UTF8-kodad JSON-data.
     * @param json JSON-data
     * @return JsonCanonicalizer
     */
    public static JsonCanonicalizer root(byte[] json) {
        try {
            return new JsonCanonicalizer(Json.DEFAULT_MAPPER.readTree(json));
        } catch (IOException e) {
            throw new RuntimeException("JSON deserialization failed", e);
        }
    }

    /**
     * Skapa instans från JSON eller POJO.
     * @param root JSON-data (byte[] eller String) eller POJO som serialiseras till JSON
     * @return JsonCanonicalizer
     */
    public static JsonCanonicalizer root(Object root) {
        return root(root, Json.DEFAULT_MAPPER);
    }

    public static JsonCanonicalizer root(Object root, ObjectMapper mapper) {
        if (root instanceof JsonNode) {
            return root((JsonNode)root).mapper(mapper);
        }

        if (root instanceof String) {
            return root((String)root).mapper(mapper);
        }

        if (root instanceof byte[]) {
            return root((byte[])root).mapper(mapper);
        }

        if (root == null) {
            return root(mapper.nullNode()).mapper(mapper);
        }

        return root(mapper.valueToTree(root)).mapper(mapper);
    }

    public JsonNode root() {
        return root;
    }

    public JsonCanonicalizer mapper(ObjectMapper mapper) {
        this.mapper = mapper;
        return this;
    }

    public JsonCanonicalizer put(String name, Object value) {
        if (!root.isObject()) {
            throw new IllegalStateException("root node is not an object: " + root.getNodeType());
        }

        ObjectNode rootObject = (ObjectNode)root;
        if (value == null) {
            rootObject.putNull(name);
        } else if (value instanceof JsonNode) {
            rootObject.set(name, (JsonNode)value);
        } else if (value instanceof String) {
            rootObject.put(name, (String)value);
        } else if (value instanceof Long) {
            rootObject.put(name, (Long)value);
        } else if (value instanceof Integer) {
            rootObject.put(name, (Integer) value);
        } else {
            rootObject.set(name, mapper.valueToTree(value));
        }

        return this;
    }

    /**
     * Konvertera till POJO.
     * @param type måltyp
     * @param <T> måltyp
     * @return instans av måltyp
     */
    public <T> T toPojo(Class<T> type) {
        try {
            return mapper.treeToValue(canonical(), type);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON to POJO mapping failed", e); // NOSONAR
        }
    }

    /**
     * Konvertera till en Map med stabil ordning.
     * @return Map
     */
    public Map<String, Object> toMap() {
        return toMap(Object.class);
    }

    /**
     * Konvertera till en Map med stabil ordning.
     * @param valueType Värdetyp
     * @param <V> Värdetyp
     * @return Map
     */
    public <V> Map<String, V> toMap(Class<V> valueType) {
        var type = mapper.getTypeFactory().constructMapLikeType(LinkedHashMap.class, String.class, valueType);
        return mapper.convertValue(canonical(), type);
    }

    /**
     * Exkludera nyckel från rotobjekt eller objekt i rotarray.
     * @param k nyckel
     * @return this
     */
    public JsonCanonicalizer exclude(String k) {
        excluded.add(k);
        return this;
    }

    /**
     * Exkludera flera nycklar från rotobjekt eller objekt i rotarray.
     * @param keys nycklar
     * @return this
     */
    public JsonCanonicalizer exclude(String ...keys) {
        excluded.addAll(Arrays.asList(keys));
        return this;
    }

    /**
     * Exkludera flera nycklar från rotobjekt eller objekt i rotarray.
     * @param keys nycklar
     * @return this
     */
    public JsonCanonicalizer exclude(Collection<String> keys) {
        excluded.addAll(keys);
        return this;
    }

    public JsonCanonicalizer include(String k) {
        excluded.remove(k);
        return this;
    }

    /**
     * Skapa normaliserad nod utan exkluderade nycklar.
     * @return JsonNode
     */
    JsonNode canonical() {
        return normalize(root, true);
    }

    private JsonNode normalize(JsonNode node, boolean filter) {
        if (node.isObject()) {
            return normalize((ObjectNode)node, filter);
        } else if (node.isArray()) {
            return normalize((ArrayNode)node, filter);
        } else if (node.isFloatingPointNumber()) {
            NumericNode nn = (NumericNode)node;
            if (!nn.isIntegralNumber()) {
                if (!nn.canConvertToLong() || Math.round(nn.doubleValue()) != nn.doubleValue()) {
                    // Not strictly true if following JavaScript spec
                    throw new IllegalArgumentException("Floating point value cannot be normalized safely: " + node);
                }

                return nn.canConvertToInt()
                    ? IntNode.valueOf(nn.intValue())
                    : LongNode.valueOf(nn.longValue());
            }
        }
        return node;
    }

    private JsonNode normalize(ObjectNode node, boolean filter) {
        final Iterator<String> it = node.fieldNames();
        final List<String> keys = new ArrayList<>(node.size());
        while (it.hasNext()) {
            String k = it.next();
            char start = k.charAt(0);
            if (!filter || !excluded.contains(k)) {
                keys.add(k);
            }
        }
        keys.sort(null);

        ObjectNode copy = mapper.getNodeFactory().objectNode();
        for (String k : keys) {
            final JsonNode v = node.get(k);
            copy.set(k, normalize(v, false));
        }

        return copy;
    }

    private JsonNode normalize(ArrayNode node, boolean filter) {
        final int n = node.size();
        ArrayNode copy = mapper.getNodeFactory().arrayNode(n);
        for (int i = 0; i < n; i++) {
            copy.add(normalize(node.get(i), filter));
        }
        return copy;
    }

    /**
     * Serialisera till normaliserad JSON utan exkluderade nycklar.
     * @return JSON i UTF8-format
     */
    public byte[] toBytes() {
        if (mapper.isEnabled(SerializationFeature.INDENT_OUTPUT)) {
            throw new IllegalStateException("Pretty printing must be disabled");
        }

        try {
            return mapper.writeValueAsBytes(canonical());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON serialization failed", e); // NOSONAR
        }
    }

    public String toBase64() {
        return Base64.getEncoder().encodeToString(toBytes());
    }

    public String toBase64Url() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(toBytes());
    }

    /**
     * Serialisera till normaliserad JSON utan exkluderade nycklar.
     * @return JSON-sträng
     */
    @Override
    public String toString() {
        if (mapper.isEnabled(SerializationFeature.INDENT_OUTPUT)) {
            throw new IllegalStateException("Pretty printing must be disabled");
        }

        try {
            return mapper.writeValueAsString(canonical());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON serialization failed", e); // NOSONAR
        }
    }

    /**
     * Serialisera till normaliserad och formaterad JSON utan exkluderade nycklar.
     * @return JSON-sträng
     */
    public String toPrettyString() {
        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(canonical());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON serialization failed", e); // NOSONAR
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JsonCanonicalizer that = (JsonCanonicalizer) o;
        if (root.getNodeType() != that.root.getNodeType() || root.size() != that.root.size()) {
            return false;
        }

        String thisNormalized = toString();
        String thatNormalized = that.toString();
        return thisNormalized.equals(thatNormalized);
    }

    @Override
    public int hashCode() {
        if (root.isArray() || root.isObject()) {
            return toString().hashCode();
        }

        return root.toString().hashCode();
    }

}
