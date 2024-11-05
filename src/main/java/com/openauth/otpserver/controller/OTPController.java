package com.openauth.otpserver.controller;

import com.openauth.otpserver.model.OTP;
import com.openauth.otpserver.service.OTPService;
import com.openauth.otpserver.service.DatabaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/otp")
public class OTPController {
    @Autowired
    private final OTPService OtpService = new OTPService();
    private final DatabaseService databaseService = new DatabaseService();

    @PostMapping("/generate")
    public ResponseEntity<String> generateOTP(@RequestParam String username) {
        System.out.println("Generating OTP for: " + username);

        String numberOTP = OtpService.generateNumberOTP();
        OTP otp = OtpService.generateOTP(username, numberOTP);
        OtpService.updateOTP(username, otp);
        System.out.println("Number OTP: " + numberOTP);

        String key = OtpService.generateKey(username, numberOTP);
        System.out.println("Hash OTP  : " + key);

        String hashedOTP = OtpService.hashOTP(key);
        System.out.println("Hashed OTP: " + hashedOTP);

        databaseService.writeCSV(username, hashedOTP);
        return ResponseEntity.ok(numberOTP);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyOTP(@RequestParam String username, @RequestParam String clientOtp) {
        OTP serverOtp = OtpService.getOTP(username);
        String enteredHash = databaseService.readCSV(username);
        if(enteredHash != null && serverOtp != null) {
            boolean isValid = OtpService.verifyOTP(clientOtp, serverOtp);
            if (isValid) {
                System.out.println("OTP verified successfully.");
                OtpService.removeOTP(username);
                databaseService.removeEntry(username);
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
