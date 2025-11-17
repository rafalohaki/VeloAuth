package net.rafalohaki.veloauth.exception;

/**
 * Base exception for VeloAuth plugin.
 * Wraps underlying exceptions with contextual information.
 */
public class VeloAuthException extends RuntimeException {

    public VeloAuthException(String message) {
        super(message);
    }

    public VeloAuthException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates a database-related exception.
     */
    public static VeloAuthException database(String operation, Throwable cause) {
        return new VeloAuthException("Database operation failed: " + operation, cause);
    }

    /**
     * Creates a configuration-related exception.
     */
    public static VeloAuthException configuration(String component, Throwable cause) {
        return new VeloAuthException("Configuration error in " + component, cause);
    }

    /**
     * Creates an authentication-related exception.
     */
    public static VeloAuthException authentication(String details, Throwable cause) {
        return new VeloAuthException("Authentication failed: " + details, cause);
    }
}
