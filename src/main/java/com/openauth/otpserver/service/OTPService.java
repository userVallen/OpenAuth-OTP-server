package com.openauth.otpserver.service;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;
import java.security.SecureRandom;

@Service
public class OTPService {
    @Value("${otp.server.key}")
    private String serverKey;
    private static final SecureRandom random = new SecureRandom();
    private final databaseService databaseService = new databaseService();

    // Generate a 6-digit numeric OTP
    public String generateOTP() {
        int otp = random.nextInt(999999);
        return String.format("%06d", otp);
    }

    public String generateKey(String username, String otp) {
        return username + serverKey + otp;
    }

    // Hash the OTP using BCrypt
    public String hashOTP(String key) {
        String time = String.valueOf(Instant.now().getEpochSecond() / 30); // 30-second time window
        String input = key + time;
        return BCrypt.hashpw(input, BCrypt.gensalt());
    }

    // Verify the OTP by comparing the hashed versions
    public boolean verifyOTP(String enteredUsername, String enteredOTP) {
        String time = String.valueOf(Instant.now().getEpochSecond() / 30); // 30-second time window
        String input = enteredUsername + serverKey + enteredOTP + time;
        String storedHash = databaseService.readCSV(enteredUsername);
        return BCrypt.checkpw(input, storedHash);
    }
}
