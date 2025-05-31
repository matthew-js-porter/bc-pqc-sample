package com.example.pqcdemo.controller;

import com.example.pqcdemo.service.MLKEMService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/hybrid")
public class HybridKeyExchangeController {

    @Autowired
    private MLKEMService mlkemService;
    
    @GetMapping("/info")
    public Map<String, String> getInfo() {
        Map<String, String> info = new HashMap<>();
        info.put("description", "Hybrid Key Exchange with ML-KEM (Kyber) and ECDH");
        info.put("mlkem", "ML-KEM (formerly Kyber) is a key encapsulation mechanism that is believed to be secure against attacks by quantum computers");
        info.put("ecdh", "Elliptic Curve Diffie-Hellman is a traditional key exchange mechanism that is secure against classical computers");
        info.put("hybrid", "A hybrid approach combines both algorithms to provide security against both classical and quantum computers");
        info.put("standardization", "ML-KEM is one of the algorithms selected by NIST for standardization as part of the post-quantum cryptography process");
        return info;
    }
    
    @GetMapping("/exchange")
    public Map<String, Object> performHybridKeyExchange(@RequestParam(defaultValue = "512") int strength) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            // Perform ML-KEM key exchange
            Map<String, String> mlkemResult = mlkemService.performKeyExchange(strength);
            result.put("mlkem", mlkemResult);
            result.put("success", true);
            result.put("message", "Hybrid key exchange completed successfully");
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        
        return result;
    }
}
