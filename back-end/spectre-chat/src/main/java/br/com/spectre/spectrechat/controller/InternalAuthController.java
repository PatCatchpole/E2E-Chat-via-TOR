package br.com.spectre.spectrechat.controller;

import br.com.spectre.spectrechat.domain.User;
import br.com.spectre.spectrechat.dto.auth.AuthCode;
import br.com.spectre.spectrechat.dto.auth.AuthLoginRequest;
import br.com.spectre.spectrechat.dto.auth.AuthRegisterRequest;
import br.com.spectre.spectrechat.dto.auth.AuthResponse;
import br.com.spectre.spectrechat.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Optional;

/**
 * Authentication.
 *
 * The previous implementation stored the client-supplied bcrypt hash verbatim
 * and compared it with String.equals. The stored value was therefore the
 * credential itself: reading the database was enough to log in as anybody.
 *
 * Now the client sends a PBKDF2 verifier and the backend applies bcrypt with a
 * random salt on top, so the stored value cannot be replayed as a login.
 */
@RestController
@RequestMapping("/internal/auth")
@RequiredArgsConstructor
public class InternalAuthController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody AuthRegisterRequest req) {
        if (userRepo.findByUsername(req.username()).isPresent()) {
            return ResponseEntity.ok(AuthResponse.failure(
                    AuthCode.USER_ALREADY_EXISTS, "Username is already taken"));
        }

        User user = User.builder()
                .username(req.username())
                .passwordHash(passwordEncoder.encode(req.verifier()))
                .role(req.role() == null ? "initiator" : req.role())
                .identityPubB64("")
                .createdAt(Instant.now())
                .build();

        try {
            userRepo.save(user);
        } catch (DataIntegrityViolationException e) {
            // Two registrations for the same name racing each other; the unique
            // constraint is the authority, not the check above.
            return ResponseEntity.ok(AuthResponse.failure(
                    AuthCode.USER_ALREADY_EXISTS, "Username is already taken"));
        }

        return ResponseEntity.ok(new AuthResponse(
                true, AuthCode.OK, user.getId(), user.getRole(), "Registered"));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthLoginRequest req) {
        Optional<User> found = userRepo.findByUsername(req.username());

        if (found.isEmpty()) {
            // Still run a comparison so that a missing user and a wrong
            // password take roughly the same time to answer.
            passwordEncoder.matches(req.verifier(), DUMMY_HASH);
            return ResponseEntity.ok(AuthResponse.failure(
                    AuthCode.USER_NOT_FOUND, "No such user"));
        }

        User user = found.get();
        if (!passwordEncoder.matches(req.verifier(), user.getPasswordHash())) {
            return ResponseEntity.ok(AuthResponse.failure(
                    AuthCode.BAD_CREDENTIALS, "Incorrect password"));
        }

        return ResponseEntity.ok(AuthResponse.ok(user.getId(), user.getRole()));
    }

    /** A well-formed bcrypt hash of a value nobody can supply, for timing parity. */
    private static final String DUMMY_HASH =
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
}
