package com.example.pqcdemo.controller;

import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class CryptoInfoController {

    @GetMapping("/crypto-providers")
    public Map<String, Object> getProviders() {
        Map<String, Object> result = new HashMap<>();
        
        // Get all security providers
        Provider[] providers = Security.getProviders();
        Map<String, String> providerMap = new HashMap<>();
        
        for (Provider provider : providers) {
            providerMap.put(provider.getName(), provider.getInfo());
        }
        
        result.put("providers", providerMap);
        
        // Get TLS information
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
            sslContext.init(null, null, null);
            
            SSLParameters params = sslContext.getDefaultSSLParameters();
            
            result.put("supportedProtocols", Arrays.asList(params.getProtocols()));
            result.put("supportedCipherSuites", Arrays.asList(params.getCipherSuites()));
            
            // Check for ML-KEM named groups
            String namedGroups = System.getProperty("jdk.tls.namedGroups", "");
            result.put("configuredNamedGroups", Arrays.asList(namedGroups.split(",\\s*")));
            
            // Check if ML-KEM is likely supported
            boolean mlkemConfigured = namedGroups.contains("kyber") || namedGroups.contains("x25519kyber");
            result.put("mlkemConfigured", mlkemConfigured);
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    @GetMapping("/tls-info")
    public Map<String, Object> getTlsInfo() throws NoSuchAlgorithmException, NoSuchProviderException {
        Map<String, Object> result = new HashMap<>();
        
        // Get TLS information from Bouncy Castle
        SSLContext sslContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);
        try {
            sslContext.init(null, null, null);
            
            // Get supported protocols
            result.put("supportedProtocols", Arrays.asList(sslContext.getSupportedSSLParameters().getProtocols()));
            
            // Get supported cipher suites
            String[] cipherSuites = sslContext.getSupportedSSLParameters().getCipherSuites();
            result.put("supportedCipherSuites", Arrays.asList(cipherSuites));
            
            // Check for ML-KEM/Kyber support in cipher suites
            boolean hasMLKEM = Arrays.stream(cipherSuites)
                .anyMatch(suite -> suite.contains("KYBER") || suite.contains("ML_KEM"));
            result.put("mlkemSupported", hasMLKEM);
            
            // Get named groups configuration
            String namedGroups = System.getProperty("jdk.tls.namedGroups", "");
            result.put("configuredNamedGroups", Arrays.asList(namedGroups.split(",\\s*")));
            
            // Check for hybrid key exchange configuration
            boolean hasHybrid = namedGroups.contains("x25519kyber");
            result.put("hybridKeyExchangeConfigured", hasHybrid);
            
            // Get BC JSSE provider version
            Provider provider = Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
            if (provider != null) {
                result.put("bcjsseVersion", provider.getVersionStr());
                result.put("bcjsseInfo", provider.getInfo());
            }
            
        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("errorType", e.getClass().getName());
        }
        
        return result;
    }
}
