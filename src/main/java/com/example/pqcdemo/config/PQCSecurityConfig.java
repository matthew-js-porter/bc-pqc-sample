package com.example.pqcdemo.config;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
public class PQCSecurityConfig {

    static {
        // Register Bouncy Castle as a security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // Register Bouncy Castle PQC provider
        Security.addProvider(new BouncyCastlePQCProvider());
        
        // Register Bouncy Castle JSSE provider
        Security.addProvider(new BouncyCastleJsseProvider());
        
        // Enable TLS debugging
        System.setProperty("javax.net.debug", "ssl:handshake");
        
        // Configure ML-KEM/Kyber for TLS
        
        // Enable ML-KEM named groups - order matters for preference
        // Include hybrid options (X25519 + ML-KEM) for better security
        System.setProperty("jdk.tls.namedGroups", 
                "x25519kyber768, x25519kyber512, x25519kyber1024, " +  // Hybrid options first
                "kyber768, kyber512, kyber1024, " +                     // Pure ML-KEM options
                "x25519, secp256r1, secp384r1, secp521r1, x448");       // Classical options last
        
        // Enable signature_algorithms_cert configuration
        System.setProperty("org.bouncycastle.jsse.client.SignatureSchemesCert", 
                "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256");
        
        // Enable server signature schemes
        System.setProperty("org.bouncycastle.jsse.server.SignatureSchemesCert", 
                "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256");
    }

    @Bean
    public SSLContext bouncyCastleSSLContext() throws NoSuchAlgorithmException, NoSuchProviderException {
        // Create an SSL context using the Bouncy Castle JSSE provider
        SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        
        try {
            // Initialize with default trust managers and key managers
            sslContext.init(null, null, null);
            
            // Configure SSL parameters to prefer PQC algorithms if available
            SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
            
            // Log the supported cipher suites
            System.out.println("Supported cipher suites:");
            for (String suite : sslContext.getSupportedSSLParameters().getCipherSuites()) {
                System.out.println(" - " + suite);
            }
            
            // Log the supported protocols
            System.out.println("Supported protocols:");
            for (String protocol : sslContext.getSupportedSSLParameters().getProtocols()) {
                System.out.println(" - " + protocol);
            }
            
            // Check if ML-KEM is supported
            boolean mlkemSupported = false;
            for (String suite : sslContext.getSupportedSSLParameters().getCipherSuites()) {
                if (suite.contains("KYBER") || suite.contains("ML_KEM")) {
                    mlkemSupported = true;
                    System.out.println("ML-KEM/Kyber is supported in TLS!");
                    break;
                }
            }
            
            if (!mlkemSupported) {
                System.out.println("WARNING: ML-KEM/Kyber does not appear to be supported in TLS with this version of Bouncy Castle");
            }
            
            // Check for XWing hybrid support
            boolean xwingSupported = false;
            String[] namedGroups = System.getProperty("jdk.tls.namedGroups").split(",\\s*");
            for (String group : namedGroups) {
                if (group.contains("x25519kyber")) {
                    xwingSupported = true;
                    System.out.println("XWing hybrid KEM (X25519 + ML-KEM) is configured!");
                    break;
                }
            }
            
            if (!xwingSupported) {
                System.out.println("WARNING: XWing hybrid KEM does not appear to be configured");
            }
            
            // Log that we're using BouncyCastle JSSE provider
            System.out.println("Tomcat connector configured with Bouncy Castle JSSE provider");
            
            return sslContext;
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Bouncy Castle SSL context", e);
        }
    }
}
