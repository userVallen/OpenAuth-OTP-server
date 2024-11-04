package com.openauth.otpserver.service;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;

@Service
public class OTPService {
    @Value("${otp.server.key}")
    private String serverKey;

    public String generateOTP(String username) {
        String timeComponent = String.valueOf(Instant.now().getEpochSecond() / 30); // 30-second time window
        String rawInput = username + serverKey + timeComponent;
        return BCrypt.hashpw(rawInput, BCrypt.gensalt());
    }

    public boolean verifyOTP(String username, String clientOtp) {
        String timeComponent = String.valueOf(Instant.now().getEpochSecond() / 30);
        String rawInput = username + serverKey + timeComponent;
        return BCrypt.checkpw(rawInput, clientOtp);
    }
}