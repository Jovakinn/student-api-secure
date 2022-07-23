package com.example.securedemo;

import com.example.securedemo.jwt.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfig.class)
public class SecureDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureDemoApplication.class, args);
    }

}
