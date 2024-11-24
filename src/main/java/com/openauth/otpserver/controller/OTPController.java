package com.openauth.otpserver.controller;

import com.openauth.otpserver.service.OTPService;
import com.openauth.otpserver.service.DatabaseService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/otp")
@Tag(name = "OTP Controller", description = "Operations for generating and verifying OTPs")
public class OTPController {
    @Autowired
    private final OTPService otpService = new OTPService();
    private final DatabaseService databaseService = new DatabaseService();

    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> signup(
            @Parameter(description = "Username for which the OTP is to be generated", required = true)
            @RequestParam String username) throws NoSuchAlgorithmException {
        System.out.println("Generating OTP for: " + username);

        String key = otpService.generateKey(username);
        System.out.println("Key       : " + key);

        String hashedKey = otpService.hashKey(key);
        System.out.println("Hashed Key: " + hashedKey);

        String otp = otpService.generateOTP(hashedKey);

        // TODO: Change setHash to storeKey
        databaseService.setHash(username, hashedKey);

        // Create response body with message and OTP
        Map<String, String> response = new LinkedHashMap<>();
        response.put("message", "OTP generated successfully");
        response.put("hashedKey", hashedKey);
        response.put("otp", otp);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    @Operation(summary = "Verify an OTP for a user", description = "Verifies an OTP for the given username.")
    public ResponseEntity<Map<String, Object>> verifyOTP(
            @Parameter(description = "Username associated with the OTP to verify", required = true)
            @RequestParam String username,
            @Parameter(description = "OTP provided by the client for verification", required = true)
            @RequestParam String clientOtp) throws NoSuchAlgorithmException {
        Map<String, Object> response = new LinkedHashMap<>();

        // Obtain the stored key and verify client's OTP
        String storedKey = databaseService.getHash(username);
        System.out.println("storedKey is: " + storedKey);
        response = otpService.verifyOTP(clientOtp, storedKey);

        if (storedKey == null) {
            response.put("message", "User not found");
            return ResponseEntity.status(404).body(response);
        }

        String isValid = (String) response.get("status");
        System.out.println("Status is: " + isValid);
        if (isValid.equals("Valid")) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(401).body(response);
        }
    }
}
