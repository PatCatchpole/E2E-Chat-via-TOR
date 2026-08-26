-- One bundle per user per room. The upsert in InternalBundleController assumed
-- this but nothing enforced it, so a duplicate row would make the lookup throw.
ALTER TABLE key_bundles
    ADD CONSTRAINT key_bundles_user_room_unique UNIQUE (user_id, room_id);

-- The backlog query is "messages in this room with id greater than N,
-- ordered by id" on every join; without this it is a sequential scan.
CREATE INDEX IF NOT EXISTS idx_messages_room_id_id ON messages (room_id, id);

-- last_seen_message_id must point at a real message, or a client can skip its
-- own backlog by sending an arbitrary value.
ALTER TABLE room_participants
    ADD CONSTRAINT room_participants_last_seen_fk
    FOREIGN KEY (last_seen_message_id) REFERENCES messages (id) ON DELETE SET NULL;
