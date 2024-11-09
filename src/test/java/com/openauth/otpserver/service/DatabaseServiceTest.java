package com.openauth.otpserver.service;

import org.junit.jupiter.api.*;
import java.io.*;
import static org.junit.jupiter.api.Assertions.*;

class DatabaseServiceTest {

    private DatabaseService databaseService;
    private static final String TEMP_CSV_FILE = "temp_output.csv";

    @BeforeEach
    void setUp() {
        databaseService = new DatabaseService();
        // Modify the DatabaseService CSV_FILE field for testing
        setCsvFilePath(TEMP_CSV_FILE);
    }

    @AfterEach
    void tearDown() {
        File tempFile = new File(TEMP_CSV_FILE);
        if (tempFile.exists()) {
            tempFile.delete();
        }
    }

    private void setCsvFilePath(String filePath) {
        try {
            var field = DatabaseService.class.getDeclaredField("CSV_FILE");
            field.setAccessible(true);
            field.set(null, filePath);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set CSV file path for testing", e);
        }
    }

    @Test
    void testSetAndGetHash() {
        // Set a hash for a user and verify it was stored correctly
        databaseService.setHash("user1", "hash1");
        String retrievedHash = databaseService.getHash("user1");
        assertEquals("hash1", retrievedHash, "The hash should match the saved value");

        // Update the hash for the same user and verify
        databaseService.setHash("user1", "newHash");
        retrievedHash = databaseService.getHash("user1");
        assertEquals("newHash", retrievedHash, "The hash should match the updated value");
    }

    @Test
    void testGetHashForNonexistentUser() {
        // Ensure that getHash returns null for a non-existing user
        assertNull(databaseService.getHash("nonexistentUser"), "Nonexistent user should return null");
    }

    @Test
    void testRemoveEntry() {
        // Set hash for multiple users
        databaseService.setHash("user1", "hash1");
        databaseService.setHash("user2", "hash2");

        // Remove user1 and check that only user2 remains
        databaseService.removeEntry("user1");
        assertNull(databaseService.getHash("user1"), "User1 should have been removed from the file");
        assertEquals("hash2", databaseService.getHash("user2"), "User2's hash should remain unchanged");
    }
}
