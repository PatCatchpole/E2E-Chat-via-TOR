package br.com.spectre.spectrechat.repository;

import br.com.spectre.spectrechat.domain.KeyBundle;
import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface KeyBundleRepository extends JpaRepository<KeyBundle, Long> {
    Optional<KeyBundle> findByRoomAndUser(Room room, User user);
    List<KeyBundle> findByRoom(Room room);
}