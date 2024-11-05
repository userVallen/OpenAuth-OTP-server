package com.openauth.otpserver.service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class DatabaseService {
    private static final String CSV_FILE = "output.csv";
    private static final Lock lock = new ReentrantLock();

    public void writeCSV(String username, String hash) {
        lock.lock(); // Ensure thread safety
        List<String> lines = new ArrayList<>();
        boolean userFound = false;

        try (BufferedReader reader = new BufferedReader(new FileReader(CSV_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(",");
                if (values.length >= 2 && values[0].equals(username)) {
                    // Update the hash if the username is found
                    lines.add(username + "," + hash);
                    userFound = true;
                } else {
                    // Retain existing line if not the target username
                    lines.add(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // If the username was not found, add it as a new entry
        if (!userFound) {
            lines.add(username + "," + hash);
        }

        // Write the updated lines back to the CSV file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(CSV_FILE, false))) {
            for (String outputLine : lines) {
                writer.write(outputLine);
                writer.newLine();
            }
            System.out.println("Logged or updated CSV: " + username + " | " + hash);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
    }

    public String readCSV(String username) {
        String line;

        try (BufferedReader reader = new BufferedReader(new FileReader(CSV_FILE))) {
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(",");
                if (values.length >= 2 && values[0].equals(username)) {
                    return values[1]; // Return the hash if the username is found
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void removeEntry(String username) {
        lock.lock(); // Ensure thread safety
        List<String> remainingEntries = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(CSV_FILE))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] values = line.split(",");
                if (!values[0].equals(username)) {
                    remainingEntries.add(line); // Keep entries not matching the username
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Rewrite CSV file without the removed entry
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(CSV_FILE))) {
            for (String entry : remainingEntries) {
                writer.write(entry);
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
    }
}