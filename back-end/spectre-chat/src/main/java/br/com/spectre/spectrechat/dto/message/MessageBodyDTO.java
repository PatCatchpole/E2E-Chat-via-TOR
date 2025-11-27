package br.com.spectre.spectrechat.dto.message;

public record MessageBodyDTO(
        String nonce_b64,
        String ct_b64
) {}