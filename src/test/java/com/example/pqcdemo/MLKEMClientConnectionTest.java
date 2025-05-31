package com.example.pqcdemo;

import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class MLKEMClientConnectionTest {

    @LocalServerPort
    private int port;

    @BeforeAll
    public static void setUp() {
        // Register Bouncy Castle providers if not already registered
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }
        
        // Enable TLS debugging
        System.setProperty("javax.net.debug", "ssl:handshake");
        
        // Enable ML-KEM/Kyber named groups - prioritize hybrid approaches
        System.setProperty("jdk.tls.namedGroups", 
                "x25519kyber768, x25519kyber512, x25519kyber1024, " +  // Hybrid options first
                "kyber768, kyber512, kyber1024, " +                     // Pure ML-KEM options
                "x25519, secp256r1, secp384r1, secp521r1, x448");       // Classical options last
        
        // Enable signature_algorithms_cert configuration
        System.setProperty("org.bouncycastle.jsse.client.SignatureSchemesCert", 
                "ecdsa_secp256r1_sha256,rsa_pss_rsae_sha256,rsa_pkcs1_sha256");
    }
    
    @Test
    public void testTLSConnectionWithMLKEM() throws Exception {
        System.out.println("Starting ML-KEM TLS connection test...");
        
        // Create a custom SSLContext using BouncyCastle JSSE provider
        SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        
        // Initialize with a custom TrustManager that accepts all certificates (for testing only)
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
        };
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        
        // Get the default SSL parameters and ensure TLS 1.3 is used
        SSLParameters sslParameters = sslContext.getDefaultSSLParameters();
        sslParameters.setProtocols(new String[]{"TLSv1.3"});
        
        // Create connection to the server
        URL url = new URL("https://localhost:" + port + "/mlkem/info");
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setHostnameVerifier((hostname, session) -> true); // Trust all hostnames for testing
        
        // Make the connection and read the response
        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }
        }
        
        // Now that the connection is established, we can get the cipher suite
        String cipherSuite = connection.getCipherSuite();
        System.out.println("Cipher suite: " + cipherSuite);
        
        // Print the response
        System.out.println("\nResponse from server: \n" + response.toString());
        
        // Verify that the connection was successful
        assertNotNull(response, "Response should not be null");
        assertTrue(response.length() > 0, "Response should not be empty");
        
        // Check if the connection used a TLS 1.3 cipher suite
        assertTrue(cipherSuite.contains("TLS_AES") || 
                   cipherSuite.contains("TLS_CHACHA20"), 
                "Connection should use a TLS 1.3 cipher suite");
        
        System.out.println("\nTest completed successfully. The connection was established using TLS 1.3.");
        System.out.println("Check the logs above for ML-KEM/Kyber usage in the TLS handshake.");
        
        // Note: We can't directly assert ML-KEM usage as the key exchange algorithm isn't exposed in the API,
        // but the handshake debug logs should show if ML-KEM was used
    }
}
