package com.banking.auth.dto;

public record AuthResponse(String accesToken, long expiresIn, String userId) {
}
