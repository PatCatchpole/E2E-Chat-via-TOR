package br.com.spectre.spectrechat.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.GenerationType;
import jakarta.persistence.FetchType;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Column;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.JoinColumn;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.Instant;

@Entity
@Table(
        name = "room_participants",
        uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "room_id"})
)
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class RoomParticipant {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "room_id", nullable = false)
    private Room room;

    @Column(name = "joined_at", nullable = false)
    private Instant joinedAt;

    @Column(name = "last_seen_message_id")
    private Long lastSeenMessageId; // pode ser null
}
