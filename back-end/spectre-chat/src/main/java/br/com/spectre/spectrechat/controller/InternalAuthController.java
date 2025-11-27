package br.com.spectre.spectrechat.controller;

import br.com.spectre.spectrechat.domain.User;
import br.com.spectre.spectrechat.dto.auth.AuthLoginRequest;
import br.com.spectre.spectrechat.dto.auth.AuthRegisterRequest;
import br.com.spectre.spectrechat.dto.auth.AuthResponse;
import br.com.spectre.spectrechat.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/internal/auth")
@RequiredArgsConstructor
public class InternalAuthController {

    private final UserRepository userRepo;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody AuthRegisterRequest req) {
        var existing = userRepo.findByUsername(req.username());
        if (existing.isPresent()) {
            return ResponseEntity.ok(
                    new AuthResponse(false, existing.get().getId(),
                            existing.get().getRole(), "Usuário já existe")
            );
        }

        User user = User.builder()
                .username(req.username())
                .passwordHash(req.passwordHashBcrypt())  // hash já vem pronto do client
                .role(req.role())
                .identityPubB64("")
                .createdAt(Instant.now())
                .build();

        userRepo.save(user);

        return ResponseEntity.ok(
                new AuthResponse(true, user.getId(), user.getRole(), "Registro OK")
        );
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthLoginRequest req) {
        var opt = userRepo.findByUsername(req.username());
        if (opt.isEmpty()) {
            // importante: frase "Usuário não existe" pq o client olha essa string
            return ResponseEntity.ok(
                    new AuthResponse(false, null, null, "Usuário não existe")
            );
        }

        User user = opt.get();

        // comparação direta de hash (hash se torna o "segredo")
        if (!user.getPasswordHash().equals(req.passwordHashBcrypt())) {
            return ResponseEntity.ok(
                    new AuthResponse(false, user.getId(), user.getRole(), "Hash inválido")
            );
        }

        return ResponseEntity.ok(
                new AuthResponse(true, user.getId(), user.getRole(), "Login OK")
        );
    }
}
