package com.example.Test.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.Test.intities.users.User;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    public record TokenData(String subject, Instant expiresAt) {}

    public String generateToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.secret);
            Instant expiresAt = generateExpirationDate();
            return JWT.create()
                    .withIssuer("auth-api")
                    .withSubject(user.getEmail())
                    .withExpiresAt(expiresAt)
                    .sign(algorithm);

        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating token", exception);
        }
    }

    /**
     * Validate token and return TokenData (subject and expiration) or null if invalid.
     */
    public TokenData validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(this.secret);
            DecodedJWT decoded = JWT.require(algorithm)
                    .withIssuer("auth-api")
                    .build()
                    .verify(token);

            String subject = decoded.getSubject();
            Instant expiresAt = decoded.getExpiresAt().toInstant();
            return new TokenData(subject, expiresAt);

        } catch (JWTVerificationException exception) {
            return null;
        }
    }

    private Instant generateExpirationDate() {
        // use UTC for consistency
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.UTC);
    }
}
