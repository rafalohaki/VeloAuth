package net.rafalohaki.veloauth.i18n;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;
import javax.annotation.Nullable;

/**
 * Complete table of Minecraft: Java Edition client locale codes (the value the client reports in
 * its {@code ClientInformation} packet, e.g. {@code tr_tr}, {@code pt_br}, {@code lol_us}) mapped
 * to the VeloAuth language code that serves it best.
 *
 * <p>Every locale shipped by the game is listed, including regional variants, minority languages
 * and the "joke" languages. Regional variants collapse onto their base language ({@code es_mx ->
 * es}), closely related or dialectal locales map onto the nearest bundled language
 * ({@code bar -> de}, {@code szl -> pl}), and constructed/joke locales map onto English unless the
 * game itself derives them from another language ({@code rpr -> ru}).
 *
 * <p>The resolution is layered: the exact locale code is tried first, then the mapping table, then
 * the bare language, then a language-family fallback ({@code pt -> pt_br}). Operators may add
 * {@code messages_<code>.properties} files for any code in this table (for example
 * {@code messages_ar.properties}); such files are picked up automatically and take precedence over
 * the fallback mapping.
 */
public final class MinecraftLocales {

    private static final Map<String, String> TABLE;

    static {
        Map<String, String> t = new LinkedHashMap<>();
        // --- Afrikaans / Arabic / Asturian / Azerbaijani / Bashkir / Bavarian
        t.put("af_za", "af");
        t.put("ar_sa", "ar");
        t.put("ast_es", "es");
        t.put("az_az", "az");
        t.put("ba_ru", "ba");
        t.put("bar", "de");
        // --- Belarusian (Cyrillic + Latin), Bulgarian, Breton, Brabantian, Bosnian
        t.put("be_by", "be");
        t.put("be_latn", "be");
        t.put("bg_bg", "bg");
        t.put("br_fr", "fr");
        t.put("brb", "nl");
        t.put("bs_ba", "bs");
        // --- Catalan / Valencian, Chuvash, Czech, Welsh, Danish
        t.put("ca_es", "ca");
        t.put("val_es", "ca");
        t.put("cv_cu", "ru");
        t.put("cs_cz", "cs");
        t.put("cy_gb", "cy");
        t.put("da_dk", "da");
        // --- German family
        t.put("de_de", "de");
        t.put("de_at", "de");
        t.put("de_ch", "de");
        t.put("fra_de", "de");
        t.put("ksh", "de");
        t.put("nds_de", "de");
        t.put("sxu", "de");
        t.put("swg", "de");
        t.put("got", "de");
        t.put("got_de", "de");
        // --- Greek
        t.put("el_gr", "el");
        // --- English family (regional + joke locales)
        t.put("en_us", "en");
        t.put("en_gb", "en");
        t.put("en_au", "en");
        t.put("en_ca", "en");
        t.put("en_nz", "en");
        t.put("en_pt", "en");   // Pirate Speak
        t.put("en_ud", "en");   // Upside-down English
        t.put("enp", "en");     // Anglish
        t.put("enws", "en");    // Shakespearean English
        t.put("lol_us", "en");  // LOLCAT
        t.put("io_en", "en");   // Ido
        t.put("jbo_en", "en");  // Lojban
        t.put("qya_aa", "en");  // Quenya
        t.put("tlh_aa", "en");  // Klingon
        t.put("tok", "tok");    // Toki Pona
        t.put("vp_vl", "en");   // Viossa
        t.put("tzl_tzl", "en"); // Talossan
        t.put("haw_us", "en");  // Hawaiian
        t.put("mi_nz", "en");   // Maori
        t.put("moh_ca", "en");  // Mohawk
        t.put("nuk", "en");     // Nuu-chah-nulth
        t.put("oji", "en");     // Ojibwe
        t.put("gv_im", "en");   // Manx
        t.put("kw_gb", "en");   // Cornish
        t.put("gd_gb", "gd");   // Scottish Gaelic
        t.put("ga_ie", "ga");   // Irish
        t.put("ig_ng", "en");   // Igbo
        t.put("yo_ng", "yo");   // Yoruba
        t.put("so_so", "en");   // Somali
        // --- Esperanto
        t.put("eo_uy", "eo");
        // --- Spanish family
        t.put("es_es", "es");
        t.put("es_ar", "es");
        t.put("es_cl", "es");
        t.put("es_ec", "es");
        t.put("es_mx", "es");
        t.put("es_uy", "es");
        t.put("es_ve", "es");
        t.put("esan", "es");    // Andalusian
        t.put("qcb_es", "es");  // Cantabrian
        t.put("nah", "es");     // Nahuatl
        t.put("tzo_mx", "es");  // Tzotzil
        t.put("pls", "es");     // Popoloca
        t.put("gl_es", "gl");   // Galician
        t.put("eu_es", "eu");   // Basque
        // --- Estonian / Võro, Persian, Finnish, Filipino / Tagalog, Faroese
        t.put("et_ee", "et");
        t.put("vro", "et");
        t.put("fa_ir", "fa");
        t.put("fi_fi", "fi");
        t.put("fil_ph", "fil");
        t.put("tl_ph", "fil");
        t.put("fo_fo", "da");
        // --- French family
        t.put("fr_fr", "fr");
        t.put("fr_ca", "fr");
        t.put("fr_ch", "fr");
        t.put("go_fr", "fr");   // Gallo
        t.put("oc_fr", "oc");   // Occitan
        t.put("kab_dz", "fr");  // Kabyle
        // --- Frisian, Hebrew / Yiddish, Hindi, Croatian, Hungarian, Armenian
        t.put("fy_nl", "fy");
        t.put("he_il", "he");
        t.put("yi_de", "he");
        t.put("hi_in", "hi");
        t.put("hr_hr", "hr");
        t.put("hu_hu", "hu");
        t.put("hy_am", "hy");
        // --- Indonesian / Malay
        t.put("id_id", "id");
        t.put("qid", "id");       // Indonesian (pre-reform spelling)
        t.put("ms_my", "ms");
        t.put("zlm_arab", "ms");  // Malay (Jawi)
        // --- Icelandic, Interslavic, Italian family
        t.put("is_is", "is");
        t.put("isv", "ru");
        t.put("it_it", "it");
        t.put("fur_it", "it");
        t.put("vec_it", "it");
        t.put("lmo", "it");
        t.put("scn", "it");
        // --- Japanese, Georgian, Kazakh, Kannada, Korean, Kyrgyz
        t.put("ja_jp", "ja");
        t.put("ka_ge", "ka");
        t.put("kk_kz", "kk");
        t.put("kn_in", "kn");
        t.put("ko_kr", "ko");
        t.put("ky_kg", "ky");
        // --- Latin, Luxembourgish, Limburgish, Lao, Lithuanian, Latvian
        t.put("la_la", "la");
        t.put("lb_lu", "lb");
        t.put("li_li", "nl");
        t.put("lo_la", "en");
        t.put("lt_lt", "lt");
        t.put("lv_lv", "lv");
        // --- Macedonian, Mongolian, Maltese
        t.put("mk_mk", "mk");
        t.put("mn_mn", "mn");
        t.put("mt_mt", "mt");
        // --- Dutch family
        t.put("nl_nl", "nl");
        t.put("nl_be", "nl");
        // --- Norwegian family + Sami
        t.put("no_no", "no");
        t.put("nb_no", "no");
        t.put("nn_no", "nn");
        t.put("hn_no", "nn");
        t.put("se_no", "no");
        // --- Elfdalian (Swedish), Polish / Silesian, Portuguese
        t.put("ovd", "sv");
        t.put("pl_pl", "pl");
        t.put("szl", "pl");
        t.put("pt_br", "pt_br");
        t.put("pt_pt", "pt_br");
        // --- Romanian, Russian family, Rusyn / Halychian -> Ukrainian
        t.put("ro_ro", "ro");
        t.put("ru_ru", "ru");
        t.put("rpr", "ru");
        t.put("sah_sah", "ru");
        t.put("tt_ru", "tt");
        t.put("ry_ua", "uk");
        t.put("hal_ua", "uk");
        t.put("uk_ua", "uk");
        // --- Slovak, Slovenian (bundled as "si"), Albanian, Serbian, Swedish
        t.put("sk_sk", "sk");
        t.put("sl_si", "si");
        t.put("sq_al", "sq");
        t.put("sr_sp", "sr");
        t.put("sr_cs", "sr");
        t.put("sv_se", "sv");
        // --- Tamil, Thai, Turkish, Uzbek, Vietnamese
        t.put("ta_in", "ta");
        t.put("th_th", "th");
        t.put("tr_tr", "tr");
        t.put("uz_uz", "uz");
        t.put("vi_vn", "vi");
        // --- Chinese family
        t.put("zh_cn", "zh_cn");
        t.put("zh_hk", "zh_hk");
        t.put("zh_tw", "zh_hk");
        t.put("lzh", "zh_cn");
        TABLE = Collections.unmodifiableMap(t);
    }

    private MinecraftLocales() {
    }

    /** All Minecraft locale codes known to this table. */
    public static Set<String> knownLocaleCodes() {
        return Collections.unmodifiableSet(new TreeSet<>(TABLE.keySet()));
    }

    /**
     * Normalizes a Java {@link Locale} back into the Minecraft {@code lang_region} form.
     * Velocity builds the locale from the client string via {@code Locale.forLanguageTag}, so
     * scripts ({@code be_latn}, {@code zlm_arab}) end up in the script component.
     */
    public static String toMinecraftCode(Locale locale) {
        if (locale == null) {
            return "";
        }
        String lang = locale.getLanguage().toLowerCase(Locale.ROOT);
        if (lang.isEmpty()) {
            return "";
        }
        for (String suffix : new String[] {locale.getCountry(), locale.getScript(), locale.getVariant()}) {
            if (suffix != null && !suffix.isEmpty()) {
                return lang + "_" + suffix.toLowerCase(Locale.ROOT);
            }
        }
        return lang;
    }

    /**
     * Resolves the best VeloAuth language code for a client locale.
     *
     * @param locale      the client's locale (may be {@code null})
     * @param supported   predicate telling whether a VeloAuth language code is available
     * @param fallback    language returned when nothing matches
     * @return a supported language code, never {@code null}
     */
    public static String resolve(Locale locale, Predicate<String> supported, String fallback) {
        String code = toMinecraftCode(locale);
        if (code.isEmpty()) {
            return fallback;
        }
        return resolve(code, supported, fallback);
    }

    /** Same as {@link #resolve(Locale, Predicate, String)} but from the raw Minecraft code. */
    public static String resolve(String minecraftCode, Predicate<String> supported, String fallback) {
        if (minecraftCode == null || minecraftCode.isBlank()) {
            return fallback;
        }
        String code = minecraftCode.toLowerCase(Locale.ROOT).replace('-', '_');
        int underscore = code.indexOf('_');
        String lang = underscore > 0 ? code.substring(0, underscore) : code;
        // In order: exact code as a language file (zh_hk, pt_br, an operator-added es_mx), the
        // curated Minecraft -> VeloAuth table, the bare language part, the table entry for the
        // bare language ("bar", "tok"), and finally a single language-family variant.
        String resolved = firstSupported(supported, code, TABLE.get(code), lang, TABLE.get(lang));
        if (resolved != null) {
            return resolved;
        }
        String family = singleFamilyVariant(lang, supported);
        return family != null ? family : fallback;
    }

    @Nullable
    private static String firstSupported(Predicate<String> supported, String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && supported.test(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    /** {@code pt -> pt_br} when exactly one {@code pt_*} file exists, otherwise {@code null}. */
    @Nullable
    private static String singleFamilyVariant(String lang, Predicate<String> supported) {
        String family = null;
        for (String candidate : BuiltInLanguages.codes()) {
            if (candidate.startsWith(lang + "_") && supported.test(candidate)) {
                if (family != null) {
                    return null;
                }
                family = candidate;
            }
        }
        return family;
    }
}
