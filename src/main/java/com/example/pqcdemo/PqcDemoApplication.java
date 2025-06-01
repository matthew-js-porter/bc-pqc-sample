package com.example.pqcdemo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class PqcDemoApplication {

	public static void main(String[] args) {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
		Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
		Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);
		SpringApplication.run(PqcDemoApplication.class, args);
	}
}
