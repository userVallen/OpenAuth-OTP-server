package com.openauth.otpserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OtpserverApplication {

	public static void main(String[] args) {
		System.out.println("Starting app...");
		SpringApplication.run(OtpserverApplication.class, args);
		System.out.println("App started.");
	}

}
