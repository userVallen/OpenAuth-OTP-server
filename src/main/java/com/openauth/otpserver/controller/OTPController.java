package com.openauth.otpserver.controller;

import com.openauth.otpserver.service.OTPService;
import com.openauth.otpserver.service.databaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/otp")
public class OTPController {
    @Autowired
    private OTPService OTPService;
    private final databaseService databaseService = new databaseService();

    @PostMapping("/generate")
    public ResponseEntity<String> generateOTP(@RequestParam String username) {
        System.out.println("Generating OTP for: " + username);
        String otp = OTPService.generateOTP();
        System.out.println("Number OTP: " + otp);
        String key = OTPService.generateKey(username, otp);
        System.out.println("Hash OTP  : " + key);
        String hashedOTP = OTPService.hashOTP(key);
        System.out.println("Hashed OTP: " + hashedOTP);
        databaseService.writeCSV(username, hashedOTP);
        return ResponseEntity.ok(otp);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyOTP(@RequestParam String username, @RequestParam String otpCode) {
        String enteredHash = databaseService.readCSV(username);
        if(enteredHash != null) {
            boolean isValid = OTPService.verifyOTP(username, otpCode);
            if (isValid) {
                System.out.println("OTP verified successfully.");
                return ResponseEntity.ok("OTP verified successfully");
            } else {
                System.out.println("Invalid OTP.");
                return ResponseEntity.status(401).body("OTP verification failed");
            }
        }
        else {
            return ResponseEntity.status(404).body("Username not found");
        }
    }
}
