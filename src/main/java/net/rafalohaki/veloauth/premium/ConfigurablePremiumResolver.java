package net.rafalohaki.veloauth.premium;

import org.slf4j.Logger;

import java.util.UUID;

/**
 * Configurable premium resolver that eliminates code duplication.
 * Uses configuration data instead of separate classes for each resolver.
 */
class ConfigurablePremiumResolver extends AbstractPremiumResolver {

    private final ResolverConfig config;

    ConfigurablePremiumResolver(Logger logger, boolean enabled, int timeoutMs, ResolverConfig config) {
        super(logger, enabled, timeoutMs);
        this.config = config;
    }

    @Override
    public String id() {
        return config.id();
    }

    @Override
    protected String getEndpoint() {
        return config.endpoint();
    }

    @Override
    protected boolean isNotFoundResponse(int code) {
        return code == config.notFoundResponseCode();
    }

    @Override
    protected String extractUuidField(String responseBody) {
        return HttpJsonClient.extractStringField(responseBody, config.uuidField());
    }

    @Override
    protected String extractUsernameField(String responseBody) {
        return HttpJsonClient.extractStringField(responseBody, config.usernameField());
    }

    @Override
    protected UUID parseUuid(String uuidStr) {
        if (config.usesRawUuidFormat()) {
            UUID uuid = PremiumUuidFormatter.parseRaw32Uuid(uuidStr);
            return uuid != null ? uuid : super.parseUuid(uuidStr);
        }
        return super.parseUuid(uuidStr);
    }
}
