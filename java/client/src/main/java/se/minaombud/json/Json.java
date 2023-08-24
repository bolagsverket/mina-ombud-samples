package se.minaombud.json;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import se.minaombud.JSON;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

public class Json {

    static {
        JSON.getDefault().getMapper()
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .disable(DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE);
    }

    public static final ObjectMapper DEFAULT_MAPPER = JSON.getDefault().getMapper();
    /*
        new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
        .enable(DeserializationFeature.READ_ENUMS_USING_TO_STRING)
        .enable(SerializationFeature.WRITE_ENUMS_USING_TO_STRING)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
        .disable(DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE)
        .registerModules(new JavaTimeModule(), new JsonNullableModule());
    */

    private final ObjectMapper mapper;

    public Json() {
        this(DEFAULT_MAPPER);
    }

    public Json(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public String toPrettyString(Object v) {
        try {
            return mapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(v);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public String toString(Object v) {
        try {
            return mapper.writeValueAsString(v);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] toBytes(Object v) {
        try {
            return mapper.writeValueAsBytes(v);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public <T> T convert(Object node, Class<T> type) {
        return mapper.convertValue(node, type);
    }

    public <T> T parse(byte[] bytes, Class<T> type) {
        try {
            return mapper.readValue(bytes, type);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public <T> T parse(String s, Class<T> type) {
        try {
            return mapper.readValue(s, type);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public <V> Map<String, V> parseJsonObject(String json, Class<V> valueType) {
        try {
            var type = mapper.getTypeFactory().constructMapLikeType(LinkedHashMap.class, String.class, valueType);
            return mapper.readValue(json, type);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Map<String, Object> parseJsonObject(String json) {
        return parseJsonObject(json, Object.class);
    }

}
