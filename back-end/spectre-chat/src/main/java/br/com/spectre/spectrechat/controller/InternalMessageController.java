package br.com.spectre.spectrechat.controller;

import br.com.spectre.spectrechat.domain.Message;
import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.User;
import br.com.spectre.spectrechat.dto.message.MessageDTO;
import br.com.spectre.spectrechat.dto.message.SaveMessageInternalRequest;
import br.com.spectre.spectrechat.repository.MessageRepository;
import br.com.spectre.spectrechat.repository.RoomRepository;
import br.com.spectre.spectrechat.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.List;


@RestController
@RequestMapping("/internal/rooms")
@RequiredArgsConstructor
public class InternalMessageController {

    private static final Logger log = LoggerFactory.getLogger(InternalMessageController.class);
    private final UserRepository userRepo;
    private final RoomRepository roomRepo;
    private final MessageRepository msgRepo;
    private final ObjectMapper mapper;

    @PostMapping("/{keyword}/messages")
    public ResponseEntity<MessageDTO> saveMessage(
            @PathVariable String keyword,
            @RequestBody SaveMessageInternalRequest req) throws Exception {

        Room room = roomRepo.findByKeyword(keyword)
                .orElseThrow(() -> new RuntimeException("Room inexistente"));

        User sender = null;
        if (req.user() != null && !req.user().isBlank()) {
            sender = userRepo.findByUsername(req.user()).orElse(null);
        }

        String headerJson = mapper.writeValueAsString(req.header());
        String bodyJson   = mapper.writeValueAsString(req.body());

        Message m = Message.builder()
                .room(room)
                .sender(sender)
                .headerJson(headerJson)
                .bodyJson(bodyJson)
                .createdAt(Instant.now())
                .build();

        Message saved = msgRepo.save(m);

        MessageDTO dto = new MessageDTO(
                saved.getId(),
                saved.getSender() != null ? saved.getSender().getUsername() : null,
                saved.getHeaderJson(),
                saved.getBodyJson(),
                saved.getCreatedAt()
        );

        log.info("DTO", dto);

        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    @GetMapping("/{keyword}/messages")
    public ResponseEntity<List<MessageDTO>> listMessages(
            @PathVariable String keyword,
            @RequestParam(required = false) Long sinceId) {

        Room room = roomRepo.findByKeyword(keyword)
                .orElseThrow(() -> new RuntimeException("Room inexistente"));

        List<Message> msgs = (sinceId == null)
                ? msgRepo.findByRoomOrderByIdAsc(room)
                : msgRepo.findByRoomAndIdGreaterThanOrderByIdAsc(room, sinceId);

        List<MessageDTO> result = msgs.stream()
                .map(m -> new MessageDTO(
                        m.getId(),
                        m.getSender() != null ? m.getSender().getUsername() : null,
                        m.getHeaderJson(),
                        m.getBodyJson(),
                        m.getCreatedAt()
                ))
                .toList();

        return ResponseEntity.ok(result);
    }
}
