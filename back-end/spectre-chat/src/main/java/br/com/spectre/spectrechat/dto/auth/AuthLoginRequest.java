package br.com.spectre.spectrechat.dto.auth;

public record AuthLoginRequest(
        String username,
        String passwordHashBcrypt,
        String role
) {}