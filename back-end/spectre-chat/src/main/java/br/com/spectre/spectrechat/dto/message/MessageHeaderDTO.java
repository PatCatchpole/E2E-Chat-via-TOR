package br.com.spectre.spectrechat.dto.message;

public record MessageHeaderDTO(
        String dh_pub_b64,
        int n
) {}