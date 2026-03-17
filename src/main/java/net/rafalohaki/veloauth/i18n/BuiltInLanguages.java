package net.rafalohaki.veloauth.i18n;

import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Central definition of bundled language codes and resource file names.
 */
public final class BuiltInLanguages {

    private static final String MESSAGES_PREFIX = "messages_";
    private static final String PROPERTIES_SUFFIX = ".properties";
    private static final String ENGLISH_CODE = "en";
    private static final String[] CODES = {
            "en", "pl", "si", "ru", "tr", "fr", "de", "fi",
            "zh_cn", "zh_hk", "ja", "hi", "vi",
            "ko", "th", "id", "pt_br"
    };

    private BuiltInLanguages() {
    }

    public static String englishCode() {
        return ENGLISH_CODE;
    }

    public static String englishFileName() {
        return fileNameFor(ENGLISH_CODE);
    }

    public static String[] codes() {
        return CODES.clone();
    }

    public static String[] fileNames() {
        String[] fileNames = new String[CODES.length];
        for (int index = 0; index < CODES.length; index++) {
            fileNames[index] = fileNameFor(CODES[index]);
        }
        return fileNames;
    }

    public static boolean isBuiltIn(String language) {
        if (language == null || language.isBlank()) {
            return false;
        }

        String normalizedLanguage = language.toLowerCase(Locale.ROOT);
        for (String code : CODES) {
            if (code.equals(normalizedLanguage)) {
                return true;
            }
        }
        return false;
    }

    public static String fileNameFor(String language) {
        return MESSAGES_PREFIX + language.toLowerCase(Locale.ROOT) + PROPERTIES_SUFFIX;
    }

    public static String quotedCodeList() {
        return Arrays.stream(CODES)
                .map(code -> '"' + code + '"')
                .collect(Collectors.joining(", "));
    }
}
