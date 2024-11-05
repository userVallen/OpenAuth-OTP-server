package com.openauth.otpserver.service;

import com.openauth.otpserver.model.OTP;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OTPService {
    @Value("${otp.server.key}")
    private String serverKey;
    private static final SecureRandom random = new SecureRandom();
    private final ConcurrentHashMap<String, OTP> OTPStore = new ConcurrentHashMap<>(); // Thread-safe map to store OTPs

    // Generate a 6-digit numeric OTP
    public String generateNumberOTP() {
        int otp = random.nextInt(999999);
        return String.format("%06d", otp);
    }

    public OTP generateOTP(String username, String otp) {
        long timestamp = Instant.now().getEpochSecond();
        return new OTP(username, otp, timestamp);
    }

    public String generateKey(String username, String otp) {
        return username + serverKey + otp;
    }

    // Hash the OTP.java using BCrypt
    public String hashOTP(String key) {
        String time = String.valueOf(Instant.now().getEpochSecond());
        String input = key + time;
        return BCrypt.hashpw(input, BCrypt.gensalt());
    }

    // Verify the OTP by comparing the hashed versions
    public boolean verifyOTP(String enteredOTP, OTP inputOTP) {
        if (!inputOTP.getOtp().equals(enteredOTP)) {
            return false;
        }

        // Check if the OTP is still valid (30 seconds)
        long currentTime = Instant.now().getEpochSecond();
        return (currentTime - inputOTP.getTimestamp() <= 30);
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
