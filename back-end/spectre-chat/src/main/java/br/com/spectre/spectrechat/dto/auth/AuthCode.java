package br.com.spectre.spectrechat.dto.auth;

/** Stable, language-independent outcomes for an auth attempt. */
public enum AuthCode {
    OK,
    USER_NOT_FOUND,
    BAD_CREDENTIALS,
    USER_ALREADY_EXISTS,
    INVALID_REQUEST
}
