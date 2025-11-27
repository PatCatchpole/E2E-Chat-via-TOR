package br.com.spectre.spectrechat.controller;

import br.com.spectre.spectrechat.domain.KeyBundle;
import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.User;
import br.com.spectre.spectrechat.dto.bundle.SaveBundleInternalRequest;
import br.com.spectre.spectrechat.repository.KeyBundleRepository;
import br.com.spectre.spectrechat.repository.RoomRepository;
import br.com.spectre.spectrechat.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;

@RestController
@RequestMapping("/internal/rooms")
@RequiredArgsConstructor
public class InternalBundleController {

    private final UserRepository userRepo;
    private final RoomRepository roomRepo;
    private final KeyBundleRepository bundleRepo;
    private final ObjectMapper mapper;

    @PostMapping("/{keyword}/bundles")
    public ResponseEntity<?> saveBundle(
            @PathVariable String keyword,
            @RequestBody SaveBundleInternalRequest req) throws Exception {

        User user = userRepo.findByUsername(req.user())
                .orElseThrow(() -> new RuntimeException("Usuário inexistente"));

        Room room = roomRepo.findByKeyword(keyword)
                .orElseThrow(() -> new RuntimeException("Room inexistente"));

        String json = mapper.writeValueAsString(req.bundle());

        KeyBundle kb = bundleRepo.findByRoomAndUser(room, user)
                .orElse(KeyBundle.builder()
                        .user(user)
                        .room(room)
                        .createdAt(Instant.now())
                        .build());

        kb.setRole(req.bundle().role());
        kb.setBundleJson(json);

        bundleRepo.save(kb);

        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
