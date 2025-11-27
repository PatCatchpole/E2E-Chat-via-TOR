package br.com.spectre.spectrechat.dto.message;

public record SaveMessageInternalRequest(
        String user,
        MessageHeaderDTO header,
        MessageBodyDTO body
) {}