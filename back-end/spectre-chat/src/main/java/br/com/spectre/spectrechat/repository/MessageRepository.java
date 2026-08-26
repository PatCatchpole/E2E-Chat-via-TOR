package br.com.spectre.spectrechat.repository;

import br.com.spectre.spectrechat.domain.Message;
import br.com.spectre.spectrechat.domain.Room;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface MessageRepository extends JpaRepository<Message, Long> {

    List<Message> findByRoomOrderByIdAsc(Room room);

    List<Message> findByRoomAndIdGreaterThanOrderByIdAsc(Room room, Long id);

    boolean existsByIdAndRoom(Long id, Room room);

    @Query("select max(m.id) from Message m where m.room = :room")
    Optional<Long> findMaxIdByRoom(@Param("room") Room room);
}