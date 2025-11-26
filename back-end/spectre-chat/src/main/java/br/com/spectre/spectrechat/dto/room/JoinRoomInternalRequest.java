package br.com.spectre.spectrechat.dto.room;

public record JoinRoomInternalRequest(
        String room,
        String user
) {}