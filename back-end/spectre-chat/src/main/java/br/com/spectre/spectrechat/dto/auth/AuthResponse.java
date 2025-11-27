package br.com.spectre.spectrechat.dto.auth;

public record AuthResponse(
        boolean valid,
        Long userId,
        String role,
        String message
) {}