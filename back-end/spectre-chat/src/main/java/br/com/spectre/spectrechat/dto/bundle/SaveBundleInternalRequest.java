package br.com.spectre.spectrechat.dto.bundle;

public record SaveBundleInternalRequest(
        String user,
        KeyBundlePayload bundle
) {}