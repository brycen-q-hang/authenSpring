package com.example.Test.intities.users.dtos;

public record LoginResponseDTO(
        String token,
        String office,
        String role,
        String permissions,
        String expires_at) {
}
