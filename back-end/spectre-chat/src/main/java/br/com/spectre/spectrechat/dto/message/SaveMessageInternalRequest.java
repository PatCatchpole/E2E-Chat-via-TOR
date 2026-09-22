package br.com.spectre.spectrechat.dto.message;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.JsonNode;

/**
 * The header and body are opaque JSON, deliberately.
 *
 * They used to be typed records -- MessageHeaderDTO(dh_pub_b64, n) and
 * MessageBodyDTO(nonce_b64, ct_b64) -- while the ratchet emits (dh, pn, n)
 * and (nonce, ct). Jackson dropped every field whose name did not match, so
 * the backend stored {"dh_pub_b64":null,"n":3} and {"nonce_b64":null,
 * "ct_b64":null}: the DH public key, the previous-chain length and the
 * ciphertext itself were all discarded on the way into the database.
 *
 * The header is AEAD associated data, so it has to come back byte for byte or
 * the tag will not verify. A typed record cannot promise that -- it destroys
 * anything it was not told about, which makes any future header field a
 * silent wire break. The backend holds ciphertext it must not interpret, so
 * it carries the JSON through untouched. MessageWireFormatTest pins this.
 *
 * The call site's @Valid did nothing before: this record declared no
 * constraints at all, unlike AuthRegisterRequest.
 */
public record SaveMessageInternalRequest(
        @Size(max = 100)
        @Pattern(regexp = "^[A-Za-z0-9._-]*$", message = "username may contain letters, digits, dot, underscore and hyphen only")
        String user,

        /** Who this copy is encrypted for; one row per recipient. */
        @Size(max = 100)
        @Pattern(regexp = "^[A-Za-z0-9._-]*$", message = "username may contain letters, digits, dot, underscore and hyphen only")
        String recipient,

        @NotNull JsonNode header,
        @NotNull JsonNode body
) {}
