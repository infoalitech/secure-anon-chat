-- Users table (minimal, no PII)
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username_hash VARCHAR(128) UNIQUE, -- Hash of username for lookup
    public_key TEXT, -- User's long-term public key
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP,
    is_ephemeral BOOLEAN DEFAULT true
);

-- Messages table (encrypted content)
CREATE TABLE messages (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_id UUID NOT NULL,
    sender_id UUID NOT NULL,
    encrypted_content TEXT NOT NULL, -- E2EE encrypted
    content_hash VARCHAR(128), -- For integrity verification
    metadata JSONB, -- Encrypted metadata
    created_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);

-- Rooms table
CREATE TABLE rooms (
    room_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    room_name_hash VARCHAR(128),
    is_private BOOLEAN DEFAULT false,
    created_by UUID,
    created_at TIMESTAMP DEFAULT NOW(),
    ephemeral_key TEXT, -- Ephemeral room key (encrypted)
    members JSONB -- Encrypted member list
);

-- Sessions table (ephemeral)
CREATE TABLE sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    session_key_hash VARCHAR(128),
    websocket_id VARCHAR(256),
    ip_hash VARCHAR(128), -- Hashed IP for rate limiting only
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);