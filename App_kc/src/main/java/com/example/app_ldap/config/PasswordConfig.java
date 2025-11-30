package com.example.app_ldap.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Configuration
public class PasswordConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                try {
                    // 1. Crea l'hash SHA-512
                    MessageDigest digest = MessageDigest.getInstance("SHA-512");
                    byte[] encoded = digest.digest(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
                    
                    // 2. Converte in Base64
                    String base64Hash = Base64.getEncoder().encodeToString(encoded);
                    
                    // 3. Aggiunge il prefisso
                    return "{SHA512}" + base64Hash;
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("Algoritmo SHA-512 non trovato!", e);
                }
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return encodedPassword.equals(encode(rawPassword));
            }
        };
    }
}