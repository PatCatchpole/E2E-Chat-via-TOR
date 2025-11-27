package br.com.spectre.spectrechat.repository;

import br.com.spectre.spectrechat.domain.Room;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoomRepository extends JpaRepository<Room, Long> {
    Optional<Room> findByKeyword(String keyword);
}
