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

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/otp")
@Tag(name = "OTP Controller", description = "Operations for generating and verifying OTPs")
public class OTPController {
    @Autowired
    private final OTPService otpService = new OTPService();
    private final DatabaseService databaseService = new DatabaseService();

    @PostMapping("/generate")
    public ResponseEntity<Map<String, String>> generateOTP(
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

        // Create response body with message and OTP
        Map<String, String> response = new LinkedHashMap<>();
        response.put("message", "OTP generated successfully");
        response.put("otp", shortenedOTP);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    @Operation(summary = "Verify an OTP for a user", description = "Verifies an OTP for the given username.")
    public ResponseEntity<Map<String, Object>> verifyOTP(
            @Parameter(description = "Username associated with the OTP to verify", required = true)
            @RequestParam String username,
            @Parameter(description = "OTP provided by the client for verification", required = true)
            @RequestParam String clientOtp) {
        OTP serverOtp = otpService.getOTP(username);
        String serverHash = databaseService.getHash(username);

        Map<String, Object> response = new LinkedHashMap<>();

        if (serverHash != null && serverOtp != null) {
            response = otpService.verifyOTP(clientOtp, serverOtp);
            boolean isValid = (Boolean) response.get("valid");
            String message = (String) response.get("message");

            if (isValid && "OTP verified successfully".equals(message)) {
                System.out.println("OTP verified successfully.");
                otpService.removeOTP(username);
                databaseService.removeEntry(username);
                return ResponseEntity.ok(response); // Success response
            }
            // Handle case where OTP has expired
            else if ("OTP has expired".equals(message)) {
                System.out.println("OTP has expired.");
                return ResponseEntity.status(410).body(response); // HTTP 410 Gone for expired OTP
            }
            // Handle invalid OTP case
            else if ("Invalid OTP".equals(message)) {
                System.out.println("Invalid OTP.");
                return ResponseEntity.status(401).body(response); // Unauthorized response
            }
        } else {
            response.put("message", "Username not found");
            response.put("valid", false);
            return ResponseEntity.status(404).body(response); // Not Found
        }
        return null;
    }
}
