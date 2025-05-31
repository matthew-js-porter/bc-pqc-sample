package com.example.pqcdemo;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class MLKEMKeyExchangeTest {

    private static final String ALGORITHM = "KYBER"; // ML-KEM is called KYBER in Bouncy Castle
    private static final String PROVIDER = "BCPQC";
    private static final String SECRET_ALGORITHM = "AES";

    @BeforeAll
    public static void setUp() {
        // Register Bouncy Castle PQC provider if not already registered
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    @Test
    public void testMLKEMKeyExchange() throws Exception {
        System.out.println("Testing ML-KEM key exchange...");
        
        // Test all three security levels
        testMLKEMWithStrength(512);  // ML-KEM-512 (security level 1)
        testMLKEMWithStrength(768);  // ML-KEM-768 (security level 3)
        testMLKEMWithStrength(1024); // ML-KEM-1024 (security level 5)
    }
    
    private void testMLKEMWithStrength(int strength) throws Exception {
        System.out.println("\nTesting ML-KEM-" + strength);
        
        // Get the appropriate parameter spec
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
                throw new IllegalArgumentException("Invalid ML-KEM strength: " + strength);
        }
        
        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
        keyPairGenerator.initialize(paramSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        System.out.println("Generated ML-KEM-" + strength + " key pair");
        System.out.println("Public key format: " + keyPair.getPublic().getFormat());
        System.out.println("Public key length: " + keyPair.getPublic().getEncoded().length + " bytes");
        
        // Encapsulate (generate and wrap a secret key)
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
        keyGenerator.init(new KEMGenerateSpec(keyPair.getPublic(), SECRET_ALGORITHM), new SecureRandom());
        SecretKeyWithEncapsulation encapsulated = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        
        byte[] encapsulation = encapsulated.getEncapsulation();
        byte[] sharedSecret1 = encapsulated.getEncoded();
        
        System.out.println("Encapsulation length: " + encapsulation.length + " bytes");
        System.out.println("Shared secret length: " + sharedSecret1.length + " bytes");
        System.out.println("Shared secret sample: " + 
                Base64.getEncoder().encodeToString(Arrays.copyOf(sharedSecret1, 16)) + "...");
        
        // Decapsulate (extract the secret key using the private key and encapsulation)
        keyGenerator = KeyGenerator.getInstance(ALGORITHM, PROVIDER);
        keyGenerator.init(new KEMExtractSpec(keyPair.getPrivate(), encapsulation, SECRET_ALGORITHM), new SecureRandom());
        SecretKeyWithEncapsulation decapsulated = (SecretKeyWithEncapsulation) keyGenerator.generateKey();
        
        byte[] sharedSecret2 = decapsulated.getEncoded();
        
        // Verify that both sides have the same shared secret
        boolean secretsMatch = Arrays.equals(sharedSecret1, sharedSecret2);
        System.out.println("Shared secrets match: " + secretsMatch);
        
        assertTrue(secretsMatch, "Shared secrets should match");
        assertNotNull(sharedSecret1, "Shared secret should not be null");
        assertTrue(sharedSecret1.length > 0, "Shared secret should not be empty");
        
        System.out.println("ML-KEM-" + strength + " key exchange successful!");
    }
}
