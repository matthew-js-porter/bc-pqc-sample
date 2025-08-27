package com.example.pqcdemo;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, useMainMethod = SpringBootTest.UseMainMethod.ALWAYS)
class PqcDemoApplicationTest {

    @LocalServerPort
    private int port;
    /*
        openssl s_client -connect localhost:8443 -groups X25519MLKEM768 -tls1_3
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "x25519", // classical
            "X25519MLKEM768", // Hybrid X25519 + ML-KEM-768,
    })
    void connectsWithConfiguredGroupName(final String groupName) throws KeyManagementException, NoSuchAlgorithmException, NoSuchProviderException {
        // Create a trust manager that accepts all certificates
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    // No validation
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    // No validation
                }
            }
        };
        
        // Create SSLContext using BCJSSE
        SSLContext context = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        context.init(null, trustAllCerts, null);

        SSLSocketFactory factory = context.getSocketFactory();
        assertThatCode(() -> {
            try (SSLSocket socket = (SSLSocket) factory.createSocket("localhost", port)) {
                SSLParameters params = socket.getSSLParameters();

                // Explicitly set the named group in the SSL parameters
                params.setNamedGroups(new String[]{groupName});
                socket.setSSLParameters(params);

                socket.startHandshake();

                System.out.println("TLS Protocol: " + socket.getSession().getProtocol());
                System.out.println("Cipher Suite: " + socket.getSession().getCipherSuite());
                System.out.println("Connected using: " + groupName);
            }
        }).doesNotThrowAnyException();
    }
}