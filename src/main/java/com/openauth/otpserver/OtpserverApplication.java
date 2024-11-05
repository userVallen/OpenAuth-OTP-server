package com.openauth.otpserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.io.FileWriter;
import java.io.IOException;

@SpringBootApplication
public class OtpserverApplication {

	private static final String CSV_FILE = "output.csv";

	public static void main(String[] args) {
		// Register the shutdown hook to clear the CSV on program termination
		Runtime.getRuntime().addShutdownHook(new Thread(() -> clearCSV()));

		System.out.println("Starting app...");
		SpringApplication.run(OtpserverApplication.class, args);
		System.out.println("App started.");
	}

	private static void clearCSV() {
		try (FileWriter writer = new FileWriter(CSV_FILE, false)) {
			System.out.println("Clearing CSV file on program termination...");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
