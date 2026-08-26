package br.com.spectre.spectrechat.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthLoginRequest(
        @NotBlank @Size(max = 100) String username,
        @NotBlank @Size(max = 512) String verifier,
        String role
) {}
