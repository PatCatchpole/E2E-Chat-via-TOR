package br.com.spectre.spectrechat.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * `verifier` is the client-derived password verifier (PBKDF2), never a
 * password and never a finished password hash. The backend applies its own
 * randomly-salted bcrypt before storing it.
 */
public record AuthRegisterRequest(
        @NotBlank @Size(max = 100)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "username may contain letters, digits, dot, underscore and hyphen only")
        String username,

        @NotBlank @Size(max = 512)
        String verifier,

        @Pattern(regexp = "^(initiator|responder)$", message = "role must be initiator or responder")
        String role
) {}
