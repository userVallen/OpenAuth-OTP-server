package com.openauth.otpserver.model;

public class OTP {
    private String username;
    private String otp;
    private long timestamp;

    public OTP(String username, String otp, long timestamp) {
        this.username = username;
        this.otp = otp;
        this.timestamp = timestamp;
    }

    // Getters
    public String getUsername() {
        return username;
    }

    public String getOtp() {
        return otp;
    }

    public long getTimestamp() {
        return timestamp;
    }
}
