package br.com.spectre.spectrechat.dto.auth;

public record AuthRegisterRequest(
        String username,
        String passwordHashBcrypt,
        String role
) {}