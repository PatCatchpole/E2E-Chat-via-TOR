package br.com.spectre.spectrechat.repository;

import br.com.spectre.spectrechat.domain.Message;
import br.com.spectre.spectrechat.domain.Room;
import br.com.spectre.spectrechat.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface MessageRepository extends JpaRepository<Message, Long> {

    List<Message> findByRoomOrderByIdAsc(Room room);

    List<Message> findByRoomAndIdGreaterThanOrderByIdAsc(Room room, Long id);

    // Recipient-scoped variants. A null recipient means a row from before
    // group support, which every member may read, hence the OR.
    @Query("select m from Message m where m.room = :room "
           + "and (m.recipient is null or m.recipient = :recipient) "
           + "order by m.id asc")
    List<Message> findForRecipient(@Param("room") Room room,
                                   @Param("recipient") User recipient);

    @Query("select m from Message m where m.room = :room and m.id > :sinceId "
           + "and (m.recipient is null or m.recipient = :recipient) "
           + "order by m.id asc")
    List<Message> findForRecipientSince(@Param("room") Room room,
                                        @Param("recipient") User recipient,
                                        @Param("sinceId") Long sinceId);

    boolean existsByIdAndRoom(Long id, Room room);

    @Query("select max(m.id) from Message m where m.room = :room")
    Optional<Long> findMaxIdByRoom(@Param("room") Room room);
}