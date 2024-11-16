package com.openauth.otpserver.service;

import com.openauth.otpserver.model.OTP;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OTPService {
    @Value("${otp.server.key}")
    private String serverKey;
    private static final SecureRandom random = new SecureRandom();
    private final ConcurrentHashMap<String, OTP> OTPStore = new ConcurrentHashMap<>(); // Thread-safe map to store OTPs

    public String generateKey(String username) {
        String timeComponent = String.valueOf(Instant.now().getEpochSecond());
        return username + serverKey + timeComponent;
    }

    public OTP generateOTP(String username, String shortenedOTP) {
        long timestamp = Instant.now().getEpochSecond();
        return new OTP(username, shortenedOTP, timestamp);
    }

    // Hash the OTP using BCrypt
    public String hashOTP(String key) {
        return BCrypt.hashpw(key, BCrypt.gensalt());
    }

    public String shortenOTP (String hashOTP) {
        String substring = hashOTP.substring(hashOTP.length() - 4);
        int numericValue = substring.hashCode(); // Generate an integer from the substring

        int otpNumber = 100000 + Math.abs(numericValue) % 900000; // Map to a 6-digit range (100000-999999)

        return String.valueOf(otpNumber);
    }

    // Verify the OTP by comparing the hashed versions
    public Map<String, Object> verifyOTP(String enteredOTP, OTP inputOTP) {
        Map<String, Object> response = new LinkedHashMap<>();

        // Check if the OTP is still valid (30 seconds)
        long currentTime = Instant.now().getEpochSecond();
        boolean isValid = (currentTime - inputOTP.getTimestamp() <= 30);

        if (!inputOTP.getOtp().equals(enteredOTP)) {
            response.put("message", "Invalid OTP");
        }
        else {
            response.put("message", "OTP verified successfully");
        }

        if (isValid) {
            response.put("valid", true);
        } else {
            response.put("message", "OTP has expired");
            response.put("valid", false);
        }
        return response;
    }

    public void updateOTP(String username, OTP otp) {
        OTPStore.put(username, otp);
    }

    public void removeOTP(String username) {
        OTPStore.remove(username);
    }

    public OTP getOTP(String username) {
        return OTPStore.get(username);
    }
}
