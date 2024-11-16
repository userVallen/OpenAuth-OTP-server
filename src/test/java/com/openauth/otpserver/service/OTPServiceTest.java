package com.openauth.otpserver.service;

import static org.junit.jupiter.api.Assertions.*;

import com.openauth.otpserver.model.OTP;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;
import java.util.Map;

@SpringBootTest
class OTPServiceTest {
    @Autowired
    private OTPService otpService;

    @Value("${otp.server.key:defaultKey}") // Set a default key for testing purposes
    private String serverKey;

    private String username;

    @BeforeEach
    void setUp() {
        username = "testUser";
    }

    @Test
    void testGenerateKey() {
        String generatedKey = otpService.generateKey(username);
        assertNotNull(generatedKey);
        assertTrue(generatedKey.contains(serverKey));
        assertTrue(generatedKey.contains(username));
    }

    @Test
    void testGenerateOTP() {
        String shortenedOTP = "123456";
        OTP otp = otpService.generateOTP(username, shortenedOTP);
        assertNotNull(otp);
        assertEquals(username, otp.getUsername());
        assertEquals(shortenedOTP, otp.getOtp());
        assertTrue(otp.getTimestamp() > 0);
    }

    @Test
    void testHashOTP() {
        String key = "testKey";
        String hashedOTP = otpService.hashOTP(key);
        assertNotNull(hashedOTP);
        assertTrue(hashedOTP.startsWith("$2a$")); // Beginning for typical BCrypt hashed passwords
    }

    @Test
    void testShortenOTP() {
        String hashOTP = otpService.hashOTP("testKey");
        String shortenedOTP = otpService.shortenOTP(hashOTP);
        assertNotNull(shortenedOTP);
        assertEquals(6, shortenedOTP.length()); // Check that the OTP is 6 characters long
    }

    @Test
    void testVerifyOTP() {
        String shortenedOTP = "123456";
        OTP otp = otpService.generateOTP(username, shortenedOTP);

        // Test with a correct OTP
        Map<String, Object> response = otpService.verifyOTP(shortenedOTP, otp);
        assertTrue((Boolean) response.get("valid"));
        assertEquals("OTP verified successfully", response.get("message"));

        // Test with an incorrect OTP
        response = otpService.verifyOTP("wrongOTP", otp);
        assertTrue((Boolean) response.get("valid"));
        assertEquals("Invalid OTP", response.get("message"));

        // Simulate an expired OTP (setting a timestamp older than 30 seconds)
        OTP expiredOTP = new OTP(username, shortenedOTP, Instant.now().getEpochSecond() - 31);
        response = otpService.verifyOTP(shortenedOTP, expiredOTP);
        assertFalse((Boolean) response.get("valid"));
        assertEquals("OTP has expired", response.get("message"));
    }

    @Test
    void testUpdateAndGetOTP() {
        OTP otp = otpService.generateOTP(username, "123456");
        otpService.updateOTP(username, otp);

        OTP retrievedOTP = otpService.getOTP(username);
        assertNotNull(retrievedOTP);
        assertEquals(otp, retrievedOTP);
    }

    @Test
    void testRemoveOTP() {
        OTP otp = otpService.generateOTP(username, "123456");
        otpService.updateOTP(username, otp);

        otpService.removeOTP(username);
        assertNull(otpService.getOTP(username));
    }
}