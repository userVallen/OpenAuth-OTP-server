package com.openauth.otpserver.service;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Base64;
import java.util.Map;

@Service
public class OTPService {
    @Value("${otp.server.key}")
    private String serverKey;

    public String generateKey(String username) {
        return username + serverKey;
    }

    public String generateOTP(String key) throws NoSuchAlgorithmException {
        // Get the current time block
        long currentTimeBlock = System.currentTimeMillis() / 60000;

        // Combine key and time block
        String combinedKey = key + currentTimeBlock;

        // Use SHA-256 to create a hash of the key
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(combinedKey.getBytes());

        // Convert the first 4 bytes of the hash to an integer
        ByteBuffer buffer = ByteBuffer.wrap(hash);
        int hashInt = buffer.getInt();

        // Get a 6-digit OTP by taking the absolute value and limiting to 6 digits
        int otp = Math.abs(hashInt % 1_000_000);  // Modulo 1,000,000 to get a 6-digit number
        return String.format("%06d", otp);  // Pad with leading zeros if needed
    }

    // Hash the key using BCrypt
    public String hashKey(String key) {
        return BCrypt.hashpw(key, BCrypt.gensalt());
    }

    // Verify the OTP by comparing the hashed versions
    public Map<String, Object> verifyOTP(String clientOTP, String storedKey) throws NoSuchAlgorithmException {
        Map<String, Object> response = new LinkedHashMap<>();

        // Generate the OTP based on the stored key
        String generatedOtp = generateOTP(storedKey);

        // Compare the generated OTP with the user-provided OTP
        boolean isValid = generatedOtp.equals(clientOTP);

        if (isValid) {
            response.put("message", "OTP verified successfully");
            response.put("status", "Valid");
        } else {
            response.put("message", "Invalid OTP");
            response.put("status", "Invalid");
        }
        return response;
    }
}
