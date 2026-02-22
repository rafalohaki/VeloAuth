package net.rafalohaki.veloauth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Utility methods for parsing YAML configuration values.
 * Extracted from Settings for single-responsibility and reuse.
 */
class YamlParserUtils {

    private static final Logger logger = LoggerFactory.getLogger(YamlParserUtils.class);

    private YamlParserUtils() {}

    static String getString(Map<String, Object> map, String key, String defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getString, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            return value.toString();
        } catch (Exception e) {
            logger.warn("Error converting value to string for key '{}', using default: {}", key, defaultValue);
            return defaultValue;
        }
    }

    static int getInt(Map<String, Object> map, String key, int defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getInt, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Invalid integer value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    static long getLong(Map<String, Object> map, String key, long defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getLong, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Invalid long value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    static boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getBoolean, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean bool) {
            return bool;
        }
        try {
            return Boolean.parseBoolean(value.toString());
        } catch (Exception e) {
            logger.warn("Invalid boolean value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    static double getDouble(Map<String, Object> map, String key, double defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getDouble, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Invalid double value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }
}
