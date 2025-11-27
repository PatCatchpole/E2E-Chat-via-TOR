package br.com.spectre.spectrechat.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.GenerationType;
import jakarta.persistence.FetchType;
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
@Table(name = "messages")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class Message {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "room_id", nullable = false)
    private Room room;

    @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = "sender_id")
    private User sender; // opcional (pode ser null)

    @Column(name = "header_json", nullable = false, columnDefinition = "TEXT")
    private String headerJson;

    @Column(name = "body_json", nullable = false, columnDefinition = "TEXT")
    private String bodyJson;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
}
