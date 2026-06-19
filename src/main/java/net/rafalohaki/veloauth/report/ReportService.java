package net.rafalohaki.veloauth.report;

import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.config.Settings;

/**
 * Public gateway for the {@code /vauth report} flow.
 * <p>
 * Assembles a diagnostic report (redacted config + velocity.toml + logs + metadata) via
 * {@link ReportGenerator}, uploads it to mclo.gs via {@link McLogsClient}, and returns the
 * public URL or an error message. This is the only public entry point in the
 * {@code net.rafalohaki.veloauth.report} package — {@link ReportGenerator},
 * {@link McLogsClient}, {@link LogReader} and {@link ReportRedactor} are package-private.
 * <p>
 * The call is blocking (file I/O + HTTP) and must run on a virtual thread, never on a
 * Velocity event thread. The caller is responsible for scheduling.
 */
public final class ReportService {

    private final ReportGenerator generator;

    public ReportService(VeloAuth plugin, Settings settings) {
        this.generator = new ReportGenerator(plugin, settings);
    }

    /**
     * Generates the report and uploads it to mclo.gs.
     *
     * @return {@link ReportResult} with the public URL on success or an error message on failure
     */
    public ReportResult generateAndUpload() {
        ReportGenerator.ReportContent content = generator.generate();
        McLogsClient.UploadResult upload = McLogsClient.upload(content.body(), content.metadata());
        if (upload.success()) {
            return ReportResult.success(upload.url());
        }
        return ReportResult.failure(upload.error());
    }

    /** Result of a report upload — carrier for the public URL or an error message. */
    public record ReportResult(boolean success, String url, String error) {
        public static ReportResult success(String url) {
            return new ReportResult(true, url, null);
        }

        public static ReportResult failure(String error) {
            return new ReportResult(false, null, error);
        }
    }
}
