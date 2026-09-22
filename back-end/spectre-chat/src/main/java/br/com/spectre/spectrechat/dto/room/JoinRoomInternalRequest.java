package br.com.spectre.spectrechat.dto.room;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * The call sites carry @Valid but this record carried no constraints, so the
 * annotation did nothing. A room keyword is a VARCHAR(100) and reaches the
 * client as part of a filename, so an unbounded one surfaces as a constraint
 * violation and a 500 rather than a 400.
 *
 * The patterns match AuthRegisterRequest and the USERNAME_RE in
 * tools/dev_backend.py; all three have to agree or a name that works against
 * the development backend is rejected by the real one.
 */
public record JoinRoomInternalRequest(
        @NotBlank @Size(max = 100)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "room may contain letters, digits, dot, underscore and hyphen only")
        String room,

        @NotBlank @Size(max = 100)
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "username may contain letters, digits, dot, underscore and hyphen only")
        String user
) {}
