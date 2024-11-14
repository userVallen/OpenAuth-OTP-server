package com.openauth.otpserver.controller;

import com.openauth.otpserver.model.OTP;
import com.openauth.otpserver.service.DatabaseService;
import com.openauth.otpserver.service.OTPService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = OTPController.class, excludeAutoConfiguration = SecurityAutoConfiguration.class)
class OTPControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OTPService otpService;

    @MockBean
    private DatabaseService databaseService;

    private String username;
    private String hashedOTP;
    private String shortenedOTP;

    @BeforeEach
    void setUp() {
        username = "testUser";
        hashedOTP = "hashedOTPExample";
        shortenedOTP = "123456";
    }

    @Test
    void testGenerateOTP() throws Exception {
        when(otpService.generateKey(username)).thenReturn("testKey"); // generateKey() returns "testKey"
        when(otpService.hashOTP("testKey")).thenReturn(hashedOTP); // hashOTP() returns hashedOTP
        when(otpService.shortenOTP(hashedOTP)).thenReturn(shortenedOTP); // shortenOTP() returns shortenedOTP

        // Mock OTP generation and storage
        OTP otp = new OTP(username, shortenedOTP, System.currentTimeMillis() / 1000L);
        when(otpService.generateOTP(username, shortenedOTP)).thenReturn(otp); // generateOTP() returns otp
        Mockito.doNothing().when(otpService).updateOTP(username, otp);

        Mockito.doNothing().when(databaseService).setHash(username, hashedOTP);

        mockMvc.perform(post("/otp/generate") // performs a mock HTTP POST request to the /generate endpoint
                        .param("username", username) // use the parameter "username"
                        .contentType(MediaType.APPLICATION_JSON)) // JSON request
                .andExpect(status().isOk()) // expects 200 OK as a response
                .andExpect(content().string(shortenedOTP)); // expects a shortenedOTP in the response body
    }

    // simulate a successful OTP verification
    @Test
    void testVerifyOTP_SuccessfulVerification() throws Exception {
        OTP otp = new OTP(username, shortenedOTP, System.currentTimeMillis() / 1000L); // represent the OTP stored in DB
        when(otpService.getOTP(username)).thenReturn(otp);
        when(databaseService.getHash(username)).thenReturn(hashedOTP);
        when(otpService.verifyOTP(shortenedOTP, otp)).thenReturn(true); // successful verification returns true

        // Mock successful verification and clean-up actions
        Mockito.doNothing().when(otpService).removeOTP(username);
        Mockito.doNothing().when(databaseService).removeEntry(username);

        mockMvc.perform(post("/otp/verify")
                        .param("username", username)
                        .param("clientOtp", shortenedOTP)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("OTP verified successfully"));
    }

    // simulate an invalid OTP submission
    @Test
    void testVerifyOTP_InvalidOTP() throws Exception {
        OTP otp = new OTP(username, shortenedOTP, System.currentTimeMillis() / 1000L);
        when(otpService.getOTP(username)).thenReturn(otp);
        when(databaseService.getHash(username)).thenReturn(hashedOTP);
        when(otpService.verifyOTP("wrongOTP", otp)).thenReturn(false);

        mockMvc.perform(post("/otp/verify")
                        .param("username", username)
                        .param("clientOtp", "wrongOTP")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string("OTP verification failed"));
    }

    // simulate an invalid username submission
    @Test
    void testVerifyOTP_UsernameNotFound() throws Exception {
        when(otpService.getOTP(username)).thenReturn(null);
        when(databaseService.getHash(username)).thenReturn(null);

        mockMvc.perform(post("/otp/verify")
                        .param("username", username)
                        .param("clientOtp", shortenedOTP)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(content().string("Username not found"));
    }
}
