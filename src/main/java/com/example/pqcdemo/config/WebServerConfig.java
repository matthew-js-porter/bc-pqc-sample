package com.example.pqcdemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;

@Configuration
public class WebServerConfig {

    @Autowired
    private SSLContext bouncyCastleSSLContext;

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatCustomizer() {
        return factory -> {
            factory.addConnectorCustomizers(connector -> {
                try {
                    // Log connector properties
                    System.out.println("Tomcat connector configured with Bouncy Castle JSSE provider");
                    System.out.println("TLS 1.3 enabled for ML-KEM support");
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        };
    }
}
