package net.rafalohaki.veloauth.database;

/**
 * Exception thrown when database access operations fail.
 * Provides more specific error handling than generic RuntimeException.
 */
public class DataAccessException extends RuntimeException {
    
    public DataAccessException(String message) {
        super(message);
    }
    
    public DataAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
