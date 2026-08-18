package com.banking.auth.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final String SECRET = "12345678901234567890123456789012";

    @Test
    void generatedTokenCanBeValidatedAndDecoded() {
        JwtService jwtService = new JwtService(SECRET, 60_000);

        String token = jwtService.generateToken("user-123");

        assertThat(jwtService.isValid(token)).isTrue();
        assertThat(jwtService.extractUserId(token)).isEqualTo("user-123");
        assertThat(jwtService.getExpirationMs()).isEqualTo(60_000);
    }

    @Test
    void invalidTokenIsRejected() {
        JwtService jwtService = new JwtService(SECRET, 60_000);

        assertThat(jwtService.isValid("not-a-jwt")).isFalse();
    }
}
