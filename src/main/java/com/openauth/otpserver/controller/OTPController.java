package com.openauth.otpserver.controller;

import com.openauth.otpserver.service.OTPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/otp")
public class OTPController {
    @Autowired
    private OTPService otpService;

    @PostMapping("/generate")
    public ResponseEntity<String> generateOtp(@RequestParam String username) {
        System.out.println("Generating OTP for: " + username);
        String otp = otpService.generateOTP(username);
        System.out.println("Generated OTP: " + otp);
        return ResponseEntity.ok(otp);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyOtp(@RequestParam String username, @RequestParam String otpCode) {
        boolean isValid = otpService.verifyOTP(username, otpCode);
        if (isValid) {
            return ResponseEntity.ok("OTP verified successfully");
        } else {
            System.out.println("Invalid OTP.");
            return ResponseEntity.status(401).body("OTP verification failed");
        }
    }
}
