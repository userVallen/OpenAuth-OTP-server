package com.openauth.otpserver.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OTPTest {

    @Test
    void testOTPConstructorAndGetters() {
        String username = "testUser";
        String otp = "123456";
        long timestamp = System.currentTimeMillis();

        OTP otpObject = new OTP(username, otp, timestamp);

        assertEquals(username, otpObject.getUsername());
        assertEquals(otp, otpObject.getOtp());
        assertEquals(timestamp, otpObject.getTimestamp());
    }
}
