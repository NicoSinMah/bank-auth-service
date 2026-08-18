package com.banking.auth.dto;

public record AuthResponse(String accessToken, long expiresIn, String userId) {
}
