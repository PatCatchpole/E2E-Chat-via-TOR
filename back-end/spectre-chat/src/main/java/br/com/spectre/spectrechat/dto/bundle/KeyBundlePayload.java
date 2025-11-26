package br.com.spectre.spectrechat.dto.bundle;

public record KeyBundlePayload(
        String user,
        String identity_pub_b64,
        String ephemeral_pub_b64,
        String init_dh_pub_b64,
        String role
) {}