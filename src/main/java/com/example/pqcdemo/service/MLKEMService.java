package com.example.pqcdemo.service;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class MLKEMService {

    private static final String ALGORITHM = "KYBER"; // ML-KEM is called KYBER in Bouncy Castle
    private static final String PROVIDER = "BCPQC";
    private static final String SECRET_ALGORITHM = "AES";
    
    /**
     * Generate an ML-KEM key pair
     * 
     * @param strength the key strength (512, 768, or 1024)
     * @return the generated key pair
     */
    public KeyPair generateKeyPair(int strength) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        
        // Use the appropriate KyberParameterSpec based on the requested strength
        KyberParameterSpec paramSpec;
        switch (strength) {
            case 512:
                paramSpec = KyberParameterSpec.kyber512;
                break;
            case 768:
                paramSpec = KyberParameterSpec.kyber768;
                break;
            case 1024:
                paramSpec = KyberParameterSpec.kyber1024;
                break;
            default:
                paramSpec = KyberParameterSpec.kyber512; // Default to 512
        }
        
        keyPairGenerator.initialize(paramSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }
    
    /**
     * Generate and encapsulate a shared secret using the public key
     * 
     * @param publicKey the public key
     * @return the secret key with encapsulation
     */
    public SecretKeyWithEncapsulation encapsulate(java.security.PublicKey publicKey) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
        keyGenerator.init(new KEMGenerateSpec(publicKey, SECRET_ALGORITHM), new SecureRandom());
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }
    
    /**
     * Extract the shared secret using the private key and encapsulation
     * 
     * @param privateKey the private key
     * @param encapsulation the encapsulation
     * @return the extracted secret key
     */
    public SecretKeyWithEncapsulation decapsulate(java.security.PrivateKey privateKey, byte[] encapsulation) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
        keyGenerator.init(new KEMExtractSpec(privateKey, encapsulation, SECRET_ALGORITHM), new SecureRandom());
        return (SecretKeyWithEncapsulation) keyGenerator.generateKey();
    }
    
    /**
     * Perform a complete ML-KEM key exchange
     * 
     * @param strength the key strength (512, 768, or 1024)
     * @return a map containing the key exchange details
     */
    public Map<String, String> performKeyExchange(int strength) throws Exception {
        Map<String, String> result = new HashMap<>();
        
        // Generate key pair
        KeyPair keyPair = generateKeyPair(strength);
        
        // Encapsulate
        SecretKeyWithEncapsulation encapsulated = encapsulate(keyPair.getPublic());
        byte[] encapsulation = encapsulated.getEncapsulation();
        byte[] sharedSecret1 = encapsulated.getEncoded();
        
        // Decapsulate
        SecretKeyWithEncapsulation decapsulated = decapsulate(keyPair.getPrivate(), encapsulation);
        byte[] sharedSecret2 = decapsulated.getEncoded();
        
        // Verify
        boolean secretsMatch = Arrays.equals(sharedSecret1, sharedSecret2);
        
        // Populate result
        result.put("publicKeyAlgorithm", keyPair.getPublic().getAlgorithm());
        result.put("publicKeyFormat", keyPair.getPublic().getFormat());
        result.put("publicKeyLength", String.valueOf(keyPair.getPublic().getEncoded().length));
        result.put("encapsulationLength", String.valueOf(encapsulation.length));
        result.put("sharedSecretLength", String.valueOf(sharedSecret1.length));
        result.put("secretsMatch", String.valueOf(secretsMatch));
        result.put("sharedSecretSample", Base64.getEncoder().encodeToString(Arrays.copyOf(sharedSecret1, 16)) + "...");
        
        return result;
    }
}
