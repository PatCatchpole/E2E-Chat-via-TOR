package br.com.spectre.spectrechat.dto.auth;

/**
 * `code` is the field callers should branch on. The relay previously decided
 * whether to register a user by substring-matching the Portuguese text of
 * `message`, which broke the moment the wording changed.
 */
public record AuthResponse(
        boolean valid,
        AuthCode code,
        Long userId,
        String role,
        String message
) {
    public static AuthResponse ok(Long userId, String role) {
        return new AuthResponse(true, AuthCode.OK, userId, role, "Login OK");
    }

    public static AuthResponse failure(AuthCode code, String message) {
        return new AuthResponse(false, code, null, null, message);
    }
}
