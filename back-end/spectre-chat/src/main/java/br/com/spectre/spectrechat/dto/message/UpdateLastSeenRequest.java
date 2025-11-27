package br.com.spectre.spectrechat.dto.message;

public record UpdateLastSeenRequest(
        String user,
        Long lastSeenMessageId
) {}
