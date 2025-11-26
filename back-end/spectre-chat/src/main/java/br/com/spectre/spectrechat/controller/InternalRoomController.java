package br.com.spectre.spectrechat.controller;

import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.RoomParticipant;
import br.com.spectre.spectrechat.domain.User;
import br.com.spectre.spectrechat.dto.message.UpdateLastSeenRequest;
import br.com.spectre.spectrechat.dto.room.JoinRoomInternalRequest;
import br.com.spectre.spectrechat.dto.room.JoinRoomInternalResponse;
import br.com.spectre.spectrechat.repository.MessageRepository;
import br.com.spectre.spectrechat.repository.RoomParticipantRepository;
import br.com.spectre.spectrechat.repository.RoomRepository;
import br.com.spectre.spectrechat.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;

@RestController
@RequestMapping("/internal/rooms")
@RequiredArgsConstructor
public class InternalRoomController {

    private final UserRepository userRepo;
    private final RoomRepository roomRepo;
    private final RoomParticipantRepository participantRepo;
    private final MessageRepository messageRepo;

    @PostMapping("/join")
    public ResponseEntity<JoinRoomInternalResponse> joinRoom(
            @RequestBody JoinRoomInternalRequest req) {

        User user = userRepo.findByUsername(req.user())
                .orElseThrow(() -> new RuntimeException("Usuário inexistente"));

        Room room = roomRepo.findByKeyword(req.room())
                .orElseGet(() -> roomRepo.save(
                        Room.builder()
                                .keyword(req.room())
                                .createdBy(user)
                                .createdAt(Instant.now())
                                .build()
                ));

        RoomParticipant participant = participantRepo.findByUserAndRoom(user, room)
                .orElseGet(() -> {
                    Long maxId = messageRepo.findMaxIdByRoom(room).orElse(null);
                    RoomParticipant rp = RoomParticipant.builder()
                            .user(user)
                            .room(room)
                            .joinedAt(Instant.now())
                            .lastSeenMessageId(maxId)
                            .build();
                    return participantRepo.save(rp);
                });

        Long lastSeen = participant.getLastSeenMessageId();

        return ResponseEntity.ok(
                new JoinRoomInternalResponse(room.getId(), lastSeen)
        );
    }

    @PostMapping("/{keyword}/last-seen")
    public ResponseEntity<?> updateLastSeen(
            @PathVariable String keyword,
            @RequestBody UpdateLastSeenRequest req) {

        User user = userRepo.findByUsername(req.user())
                .orElseThrow(() -> new RuntimeException("Usuário inexistente"));

        Room room = roomRepo.findByKeyword(keyword)
                .orElseThrow(() -> new RuntimeException("Room inexistente"));

        RoomParticipant participant = participantRepo.findByUserAndRoom(user, room)
                .orElseThrow(() -> new RuntimeException("Participação inexistente"));

        participant.setLastSeenMessageId(req.lastSeenMessageId());
        participantRepo.save(participant);

        return ResponseEntity.ok().build();
    }
}
