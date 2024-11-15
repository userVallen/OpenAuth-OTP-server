package com.openauth.otpserver.controller;

import com.openauth.otpserver.model.OTP;
import com.openauth.otpserver.service.OTPService;
import com.openauth.otpserver.service.DatabaseService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/otp")
@Tag(name = "OTP Controller", description = "Operations for generating and verifying OTPs")
public class OTPController {
    @Autowired
    private final OTPService otpService = new OTPService();
    private final DatabaseService databaseService = new DatabaseService();

    @PostMapping("/generate")
    public ResponseEntity<String> generateOTP(
            @Parameter(description = "Username for which the OTP is to be generated", required = true)
            @RequestParam String username) {
        System.out.println("Generating OTP for: " + username);

        String key = otpService.generateKey(username);
        System.out.println("Key       : " + key);

        String hashedOTP = otpService.hashOTP(key);
        System.out.println("Hashed OTP: " + hashedOTP);

        String shortenedOTP = otpService.shortenOTP(hashedOTP);
        System.out.println("Shortened OTP: " + shortenedOTP);

        OTP otp = otpService.generateOTP(username, shortenedOTP);
        otpService.updateOTP(username, otp);

        databaseService.setHash(username, hashedOTP);
        return ResponseEntity.ok(shortenedOTP);
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify an OTP for a user", description = "Verifies an OTP for the given username.")
    public ResponseEntity<String> verifyOTP(
            @Parameter(description = "Username associated with the OTP to verify", required = true)
            @RequestParam String username,
            @Parameter(description = "OTP provided by the client for verification", required = true)
            @RequestParam String clientOtp) {
        OTP serverOtp = otpService.getOTP(username);
        String serverHash = databaseService.getHash(username);
        if(serverHash != null && serverOtp != null) {
            boolean isValid = otpService.verifyOTP(clientOtp, serverOtp);
            if (isValid) {
                System.out.println("OTP verified successfully.");
                otpService.removeOTP(username);
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
