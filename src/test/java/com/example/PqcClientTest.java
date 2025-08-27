package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThatCode;

public class PqcClientTest {

    @BeforeAll
    static void setupProviders() {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 2);
    }

    /*
        openssl s_client -connect pq.cloudflareresearch.com:443 -groups X25519MLKEM768 -tls1_3
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "x25519", // classical
            "X25519MLKEM768", // Hybrid X25519 + ML-KEM-768,
    })
    void connectsWithConfiguredGroupName(final String groupName) throws KeyManagementException, NoSuchAlgorithmException, NoSuchProviderException {
        // Create SSLContext using BCJSSE
        SSLContext context = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        context.init(null, null, null);

        SSLSocketFactory factory = context.getSocketFactory();
        assertThatCode(() -> {
            try (SSLSocket socket = (SSLSocket) factory.createSocket("pq.cloudflareresearch.com", 443)) {
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
