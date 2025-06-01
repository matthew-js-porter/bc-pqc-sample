package com.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.Test;
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
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatCode;

public class PqcClientTest {


    /*
        openssl s_client -connect pq.cloudflareresearch.com:443 -groups X25519MLKEM768 -tls1_3
     */

    @ParameterizedTest
    @ValueSource(strings = {
            "X25519", // classical
            "X25519MLKEM768", // Hybrid X25519 + ML-KEM-768
            "X25519KYBER768", // Legacy name,
            "X25519Kyber512Draft00",
            "X25519Kyber768Draft00"
    })
    void connectsWithConfiguredGroupName(final String groupName) throws KeyManagementException, NoSuchAlgorithmException, NoSuchProviderException {
        // Register BC and BCJSSE providers
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
        Security.insertProviderAt(new BouncyCastleJsseProvider(), 1);
        Security.insertProviderAt(new BouncyCastlePQCProvider(), 2);

        // Create SSLContext using BCJSSE
        SSLContext context = SSLContext.getInstance("TLSv1.3", "BCJSSE");
        context.init(null, null, null);

        SSLSocketFactory factory = context.getSocketFactory();
        assertThatCode(() -> {
            try (SSLSocket socket = (SSLSocket) factory.createSocket("pq.cloudflareresearch.com", 443)) {
                SSLParameters params = socket.getSSLParameters();

                // List supported groups (for debug)
                System.out.println("Supported named groups: " + Arrays.toString(params.getNamedGroups()));

                // Set hybrid PQ group (if supported by server)
                params.setNamedGroups(new String[]{groupName});
                socket.setSSLParameters(params);

                socket.startHandshake();

                System.out.println("TLS Protocol: " + socket.getSession().getProtocol());
                System.out.println("Cipher Suite: " + socket.getSession().getCipherSuite());
            }
        }).doesNotThrowAnyException();
    }

    @Test
    void printNamedGroups() throws NoSuchAlgorithmException {
        SSLContext context = SSLContext.getDefault();
        SSLParameters params = context.getDefaultSSLParameters();

        String[] supportedGroups = params.getNamedGroups();

        System.out.println("🔐 Supported Named Groups:");
        Arrays.stream(supportedGroups).forEach(group -> System.out.println("  - " + group));
    }
}
