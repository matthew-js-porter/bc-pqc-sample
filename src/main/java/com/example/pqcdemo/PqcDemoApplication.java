package com.example.pqcdemo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Provider;
import java.security.Security;

@SpringBootApplication
@RestController
public class PqcDemoApplication {

	public static void main(String[] args) {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
		Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
		// Print security providers before application starts
		System.out.println("Available security providers:");
		for (Provider provider : Security.getProviders()) {
			System.out.println(" - " + provider.getName() + " - " + provider.getInfo());
		}
		
		SpringApplication.run(PqcDemoApplication.class, args);
	}
	
	@GetMapping("/")
	public String home() {
		return "Spring Boot application running over HTTPS with a self-signed certificate!";
	}
	
	@GetMapping("/providers")
	public String listProviders() {
		StringBuilder result = new StringBuilder("Security Providers:\n");
		for (Provider provider : Security.getProviders()) {
			result.append(" - ").append(provider.getName()).append(" - ").append(provider.getInfo()).append("\n");
		}
		return result.toString();
	}
}
