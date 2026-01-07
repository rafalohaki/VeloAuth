package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ValidationUtils.
 * Tests validation logic, IP extraction, and component creation.
 */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S2068", "java:S100"}) // Test passwords are test data, not production credentials
class ValidationUtilsTest {

    @Mock
    private Player mockPlayer;

    private Settings mockSettings;

    @BeforeEach
    void setUp() {
        mockSettings = new TestValidationSettings(java.nio.file.Path.of(".test-validation"), 6, 32);
    }

    @Test
    @SuppressWarnings("java:S2068") // Test passwords are test data, not production credentials
    void testValidatePassword_ValidPassword_ReturnsSuccess() {
        // Using TestValidationSettings with min=6, max=32
        String validPassword = "testPassword123"; // NOSONAR - Test password for validation
        
        ValidationUtils.ValidationResult result = ValidationUtils.validatePassword(validPassword, mockSettings);

        assertTrue(result.valid());
        assertNull(result.getErrorMessage());
    }

    @Test
    void testValidatePassword_EmptyPassword_ReturnsError() {
        ValidationUtils.ValidationResult result = ValidationUtils.validatePassword("", mockSettings);

        assertFalse(result.valid());
        assertEquals("validation.password.empty", result.getErrorMessage());
    }

    @Test
    void testValidatePassword_NullPassword_ReturnsError() {
        ValidationUtils.ValidationResult result = ValidationUtils.validatePassword(null, mockSettings);

        assertFalse(result.valid());
        assertEquals("validation.password.empty", result.getErrorMessage());
    }

    @Test
    @SuppressWarnings("java:S2068") // Test passwords are test data, not production credentials
    void testValidatePassword_TooShort_ReturnsError() {
        // Using TestValidationSettings with min=6
        String shortPassword = "test"; // NOSONAR - Test password

        ValidationUtils.ValidationResult result = ValidationUtils.validatePassword(shortPassword, mockSettings);

        assertFalse(result.valid());
        assertEquals("validation.password.too_short:6", result.getErrorMessage());
    }

    @Test
    void testValidatePassword_TooLong_ReturnsError() {
        // Using TestValidationSettings with max=32

        String longPassword = "a".repeat(33);

        ValidationUtils.ValidationResult result = ValidationUtils.validatePassword(longPassword, mockSettings);

        assertFalse(result.valid());
        assertEquals("validation.password.too_long:32", result.getErrorMessage());
    }

    @Test
    @SuppressWarnings("java:S2068") // Test passwords are test data, not production credentials
    void testValidatePasswordMatch_MatchingPasswords_ReturnsSuccess() {
        String password = "test123"; // NOSONAR - Test data
        String confirmPassword = "test123"; // NOSONAR - Test data

        ValidationUtils.ValidationResult result = ValidationUtils.validatePasswordMatch(password, confirmPassword);

        assertTrue(result.valid());
        assertNull(result.getErrorMessage());
    }

    @Test
    @SuppressWarnings("java:S2068") // Test passwords are test data, not production credentials
    void testValidatePasswordMatch_NonMatchingPasswords_ReturnsError() {
        String password = "testPassword123"; // NOSONAR - Test data
        String confirmPassword = "differentPassword"; // NOSONAR - Test data

        ValidationUtils.ValidationResult result = ValidationUtils.validatePasswordMatch(password, confirmPassword);

        assertFalse(result.valid());
        assertEquals("validation.password.mismatch", result.getErrorMessage());
    }

    @Test
    @SuppressWarnings("java:S5164") // Using localhost for unit test - no SSRF risk
    void testGetPlayerIp_ValidInetSocketAddress_ReturnsIp() throws java.net.UnknownHostException {
        String expectedIp = "127.0.0.1"; // Use localhost for testing
        InetAddress address = InetAddress.getByName(expectedIp); // NOSONAR - Localhost test only
        InetSocketAddress socketAddress = new InetSocketAddress(address, 25565); // NOSONAR - Test data
        when(mockPlayer.getRemoteAddress()).thenReturn(socketAddress);

        String result = PlayerAddressUtils.getPlayerIp(mockPlayer);

        assertEquals(expectedIp, result);
    }

    @Test
    void testGetPlayerAddress_ValidInetSocketAddress_ReturnsInetAddress() throws java.net.UnknownHostException {
        InetAddress address = InetAddress.getByName("192.168.1.2");
        @SuppressWarnings("java:S5164") // Using localhost/private IP for unit test - no SSRF risk
        InetSocketAddress socketAddress = new InetSocketAddress(address, 25565); // NOSONAR
        when(mockPlayer.getRemoteAddress()).thenReturn(socketAddress);

        InetAddress result = PlayerAddressUtils.getPlayerAddress(mockPlayer);

        assertEquals(address, result);
    }

    @Test
    void testValidateArgumentCount_CorrectCount_ReturnsSuccess() {
        String[] args = {"arg1", "arg2"};
        String usage = "Użycie: /command <arg1> <arg2>";

        ValidationUtils.ValidationResult result = ValidationUtils.validateArgumentCount(args, 2, usage);

        assertTrue(result.valid());
        assertNull(result.getErrorMessage());
    }

    @Test
    void testValidateArgumentCount_IncorrectCount_ReturnsError() {
        String[] args = {"arg1"};
        String usage = "Użycie: /command <arg1> <arg2>";

        ValidationUtils.ValidationResult result = ValidationUtils.validateArgumentCount(args, 2, usage);

        assertFalse(result.valid());
        assertEquals(usage, result.getErrorMessage());
    }

    @Test
    void testCreateErrorComponent_CreatesRedComponent() {
        String message = "Error message";

        var component = ValidationUtils.createErrorComponent(message);

        assertNotNull(component);
    }

    @Test
    void testCreateSuccessComponent_CreatesGreenComponent() {
        String message = "Success message";

        var component = ValidationUtils.createSuccessComponent(message);

        assertNotNull(component);
    }

    @Test
    void testCreateWarningComponent_CreatesYellowComponent() {
        String message = "Warning message";

        var component = ValidationUtils.createWarningComponent(message);

        assertNotNull(component);
    }

    @Test
    void testValidationResult_FactoryMethods() {
        // Test success factory method
        ValidationUtils.ValidationResult success = ValidationUtils.ValidationResult.success();
        assertTrue(success.valid());
        assertNull(success.getErrorMessage());

        // Test error factory method
        String errorMessage = "Test error";
        ValidationUtils.ValidationResult error = ValidationUtils.ValidationResult.error(errorMessage);
        assertFalse(error.valid());
        assertEquals(errorMessage, error.getErrorMessage());
    }
}
