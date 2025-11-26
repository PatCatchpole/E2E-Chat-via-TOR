CREATE TABLE users (
                       id               BIGSERIAL PRIMARY KEY,
                       username         VARCHAR(100) NOT NULL UNIQUE,
                       password_hash    VARCHAR(255) NOT NULL,
                       role             VARCHAR(50)  NOT NULL,
                       identity_pub_b64 TEXT         NOT NULL DEFAULT '',
                       created_at       TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE rooms (
                       id          BIGSERIAL PRIMARY KEY,
                       keyword     VARCHAR(100) NOT NULL UNIQUE,
                       created_by  BIGINT REFERENCES users(id),
                       created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE room_participants (
                                   id          BIGSERIAL PRIMARY KEY,
                                   user_id     BIGINT NOT NULL REFERENCES users(id),
                                   room_id     BIGINT NOT NULL REFERENCES rooms(id),
                                   joined_at   TIMESTAMP NOT NULL DEFAULT NOW(),
                                   UNIQUE (user_id, room_id)
);

CREATE TABLE key_bundles (
                             id          BIGSERIAL PRIMARY KEY,
                             user_id     BIGINT NOT NULL REFERENCES users(id),
                             room_id     BIGINT NOT NULL REFERENCES rooms(id),
                             role        VARCHAR(20) NOT NULL, -- initiator / responder
                             bundle_json TEXT        NOT NULL,
                             created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE TABLE messages (
                          id          BIGSERIAL PRIMARY KEY,
                          room_id     BIGINT NOT NULL REFERENCES rooms(id),
                          sender_id   BIGINT REFERENCES users(id),
                          header_json TEXT    NOT NULL,
                          body_json   TEXT    NOT NULL,
                          created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
