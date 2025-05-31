package com.example.pqcdemo.controller;

import com.example.pqcdemo.service.MLKEMService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/mlkem")
public class MLKEMController {

    @Autowired
    private MLKEMService mlkemService;
    
    @GetMapping("/exchange")
    public Map<String, String> performKeyExchange(@RequestParam(defaultValue = "512") int strength) {
        try {
            return mlkemService.performKeyExchange(strength);
        } catch (Exception e) {
            throw new RuntimeException("Error performing ML-KEM key exchange", e);
        }
    }
    
    @GetMapping("/info")
    public String getInfo() {
        return "ML-KEM (formerly Kyber) is a key encapsulation mechanism that is believed to be secure " +
               "against attacks by quantum computers. It is one of the algorithms selected by NIST for " +
               "standardization as part of the post-quantum cryptography process.";
    }
}
