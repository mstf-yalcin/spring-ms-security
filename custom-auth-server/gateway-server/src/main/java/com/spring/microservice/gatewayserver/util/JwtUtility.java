package com.spring.microservice.gatewayserver.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.function.Function;

@Component
public class JwtUtility {

    private PublicKey publicKey;

    @Value("${jwt.public-key-uri}")
    private String publicKeyUrl;

    @PostConstruct
    public void init() {
        this.publicKey = fetchPublicKey();
    }

    public PublicKey fetchPublicKey() {
        try {
            RestTemplate restTemplate = new RestTemplate();
            String publicKeyStr = restTemplate.getForObject(publicKeyUrl, String.class);
            byte[] decodedKey = Base64.getDecoder().decode(publicKeyStr);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Error while fetching public key", e);
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> function) {
        Claims payload = Jwts.parser().verifyWith(publicKey)
                .build().parseSignedClaims(token).getPayload();
        return function.apply(payload);
    }

}
