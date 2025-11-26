package br.com.spectre.spectrechat.repository;

import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.RoomParticipant;
import br.com.spectre.spectrechat.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoomParticipantRepository extends JpaRepository<RoomParticipant, Long> {
    Optional<RoomParticipant> findByUserAndRoom(User user, Room room);
    List<RoomParticipant> findByRoom(Room room);
}