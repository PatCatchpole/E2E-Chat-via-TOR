package br.com.spectre.spectrechat.controller;

import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.RoomParticipant;
import br.com.spectre.spectrechat.domain.User;
import br.com.spectre.spectrechat.dto.message.UpdateLastSeenRequest;
import br.com.spectre.spectrechat.error.NotFoundException;
import jakarta.validation.Valid;
import org.springframework.transaction.annotation.Transactional;
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
    @Transactional
    public ResponseEntity<JoinRoomInternalResponse> joinRoom(
            @Valid @RequestBody JoinRoomInternalRequest req) {

        User user = userRepo.findByUsername(req.user())
                .orElseThrow(() -> new NotFoundException("No such user: " + req.user()));

        Room room = roomRepo.findByKeyword(req.room())
                .orElseGet(() -> roomRepo.save(
                        Room.builder()
                                .keyword(req.room())
                                .createdBy(user)
                                .createdAt(Instant.now())
                                .build()
                ));

        var existingOpt = participantRepo.findByUserAndRoom(user, room);
        boolean isNewParticipant = existingOpt.isEmpty();

        RoomParticipant participant = existingOpt.orElseGet(() -> participantRepo.save(
                RoomParticipant.builder()
                        .user(user)
                        .room(room)
                        .joinedAt(Instant.now())
                        .lastSeenMessageId(null)
                        .build()
        ));


        Long lastSeen = participant.getLastSeenMessageId();


        if (isNewParticipant && lastSeen == null) {
            Long maxId = messageRepo.findMaxIdByRoom(room).orElse(null);
            if (maxId != null) {
                participant.setLastSeenMessageId(maxId);
                participantRepo.save(participant);
                lastSeen = maxId;
            }
        }

        return ResponseEntity.ok(
                new JoinRoomInternalResponse(room.getId(), lastSeen)
        );
    }


    @PostMapping("/{keyword}/last-seen")
    @Transactional
    public ResponseEntity<?> updateLastSeen(
            @PathVariable String keyword,
            @Valid @RequestBody UpdateLastSeenRequest req) {

        User user = userRepo.findByUsername(req.user())
                .orElseThrow(() -> new NotFoundException("No such user: " + req.user()));

        Room room = roomRepo.findByKeyword(keyword)
                .orElseThrow(() -> new NotFoundException("No such room: " + keyword));

        RoomParticipant participant = participantRepo.findByUserAndRoom(user, room)
                .orElseThrow(() -> new NotFoundException("User is not a participant of that room"));

        // The id comes from a client. V3 puts a foreign key on this column, so
        // an arbitrary value would surface as a constraint violation and a 500;
        // checking it here also stops a client marking messages of another room
        // as seen and skipping its own backlog.
        Long lastSeenId = req.lastSeenMessageId();
        if (lastSeenId != null && !messageRepo.existsByIdAndRoom(lastSeenId, room)) {
            throw new NotFoundException("No message " + lastSeenId + " in room " + keyword);
        }

        participant.setLastSeenMessageId(lastSeenId);
        participantRepo.save(participant);

        return ResponseEntity.ok().build();
    }
}
