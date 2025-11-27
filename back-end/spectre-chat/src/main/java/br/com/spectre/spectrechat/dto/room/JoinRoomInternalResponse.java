package br.com.spectre.spectrechat.dto.room;

public record JoinRoomInternalResponse(
        Long roomId,
        Long lastSeenMessageId
) {}
