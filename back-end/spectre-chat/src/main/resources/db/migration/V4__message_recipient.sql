-- A room is a mesh of pairwise sessions: one plaintext becomes one ciphertext
-- per recipient, each decryptable only by them. Without a recipient the relay
-- cannot tell which copy belongs to whom, and every member would be handed
-- every copy.
--
-- Nullable so rows written before this migration keep working; the relay
-- treats a NULL recipient as "deliver to anyone", matching the old behaviour.
ALTER TABLE messages ADD COLUMN recipient_id BIGINT REFERENCES users(id);

-- The backlog query is "messages in this room, for this recipient, newer
-- than N", so the index has to lead with the same columns.
CREATE INDEX IF NOT EXISTS idx_messages_room_recipient_id
    ON messages (room_id, recipient_id, id);
