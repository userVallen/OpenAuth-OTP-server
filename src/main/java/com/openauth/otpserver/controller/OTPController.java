package com.openauth.otpserver.controller;

import com.openauth.otpserver.model.OTP;
import com.openauth.otpserver.service.OTPService;
import com.openauth.otpserver.service.databaseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/otp")
public class OTPController {
    @Autowired
    private OTPService OTPService;
    private final databaseService databaseService = new databaseService();
    private final ConcurrentHashMap<String, OTP> OTPStore = new ConcurrentHashMap<>(); // Thread-safe map to store OTPs

    @PostMapping("/generate")
    public ResponseEntity<String> generateOTP(@RequestParam String username) {
        System.out.println("Generating OTP for: " + username);

        String numberOTP = OTPService.generateNumberOTP();
        OTP otp = OTPService.generateOTP(username, numberOTP);
        OTPStore.put(username, otp); // Store the OTP for the username
        System.out.println("Number OTP: " + numberOTP);

        String key = OTPService.generateKey(username, numberOTP);
        System.out.println("Hash OTP  : " + key);

        String hashedOTP = OTPService.hashOTP(key);
        System.out.println("Hashed OTP: " + hashedOTP);

        databaseService.writeCSV(username, hashedOTP);
        return ResponseEntity.ok(numberOTP);
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyOTP(@RequestParam String username, @RequestParam String otpCode) {
        OTP otp = OTPStore.get(username);
        String enteredHash = databaseService.readCSV(username);
        if(enteredHash != null && otp != null) {
            boolean isValid = OTPService.verifyOTP(otpCode, otp);
            if (isValid) {
                System.out.println("OTP verified successfully.");
                OTPStore.remove(username);
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
