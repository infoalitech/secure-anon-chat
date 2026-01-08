Client A:
1. Generate ephemeral key pair for session
2. Perform X3DH with Client B's public key
3. Derive shared secret using Double Ratchet
4. Encrypt message with AES-256-GCM
5. Send encrypted blob + ephemeral public key

Server:
1. Receive encrypted blob
2. Verify sender authentication
3. Store encrypted message
4. Route to recipient via WebSocket

Client B:
1. Receive encrypted blob
2. Use own private key + sender's ephemeral key
3. Derive same shared secret
4. Decrypt with AES-256-GCM