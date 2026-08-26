package br.com.spectre.spectrechat.dto.message;

public record SaveMessageInternalRequest(
        String user,
        /** Who this copy is encrypted for; one row per recipient. */
        String recipient,
        MessageHeaderDTO header,
        MessageBodyDTO body
) {}
