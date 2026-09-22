package br.com.spectre.spectrechat.dto;

import br.com.spectre.spectrechat.dto.message.SaveMessageInternalRequest;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The ratchet header is AEAD associated data: both peers derive the tag over
 * the exact bytes, so the backend must hand back what the sender sent, field
 * for field. Anything it does not recognise it must still carry.
 *
 * Typed records could not do that. MessageHeaderDTO declared (dh_pub_b64, n)
 * while the ratchet emits (dh, pn, n), so every stored header lost its DH
 * public key and its previous-chain length -- which made every message
 * delivered from the backlog undecryptable. Nothing caught it because the
 * Python side is exercised against tools/dev_backend.py, which stores the
 * JSON verbatim.
 */
class MessageWireFormatTest {

    /** Exactly what client/crypto/ratchet.py emits. */
    private static final String PACKET = """
            {"user":"alice","recipient":"bob",
             "header":{"dh":"4NtnPJkQYRqfOBS7LZR16N68pKyfUU5oMfHQVz6lEiU=","pn":0,"n":3},
             "body":{"nonce":"6oITxl9H8QQ3uZyTHfAGJVcvXSUWXQ6l","ct":"L696eKI91uqpCrVwpbJ+Z8XA"}}
            """;

    private final ObjectMapper mapper = new ObjectMapper();

    private SaveMessageInternalRequest parsed() {
        return mapper.readValue(PACKET, SaveMessageInternalRequest.class);
    }

    private JsonNode reserialised(Object part) {
        return mapper.readTree(mapper.writeValueAsString(part));
    }

    @Test
    void aStoredHeaderKeepsEveryFieldTheSenderSet() {
        JsonNode header = reserialised(parsed().header());

        assertTrue(header.has("dh"), "the DH public key was dropped: " + header);
        assertTrue(header.has("pn"), "the previous-chain length was dropped: " + header);
        assertTrue(header.has("n"), "the counter was dropped: " + header);
    }

    @Test
    void aStoredBodyKeepsEveryFieldTheSenderSet() {
        JsonNode body = reserialised(parsed().body());

        assertTrue(body.has("nonce"), "the nonce was dropped: " + body);
        assertTrue(body.has("ct"), "the ciphertext was dropped: " + body);
    }

    @Test
    void aHeaderRoundTripsUnchanged() {
        assertEquals(mapper.readTree(PACKET).get("header"), reserialised(parsed().header()));
    }

    @Test
    void aBodyRoundTripsUnchanged() {
        assertEquals(mapper.readTree(PACKET).get("body"), reserialised(parsed().body()));
    }

    @Test
    void anUnrecognisedHeaderFieldIsCarriedRatherThanDiscarded() {
        String future = """
                {"user":"alice","recipient":"bob",
                 "header":{"dh":"AA==","pn":0,"n":1,"future_field":"keep me"},
                 "body":{"nonce":"AA==","ct":"AA=="}}
                """;
        JsonNode header = reserialised(
                mapper.readValue(future, SaveMessageInternalRequest.class).header());

        assertTrue(header.has("future_field"),
                "a header field the backend does not know about was destroyed: " + header);
    }
}
