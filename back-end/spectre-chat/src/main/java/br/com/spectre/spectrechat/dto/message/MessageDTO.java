package br.com.spectre.spectrechat.dto.message;

import java.time.Instant;

public record MessageDTO(
        Long id,
        String sender,
        String headerJson,
        String bodyJson,
        Instant createdAt
) {}