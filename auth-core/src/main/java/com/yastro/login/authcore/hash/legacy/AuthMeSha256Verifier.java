package com.yastro.login.authcore.hash.legacy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * AuthMe SHA256. Formato {@code $SHA$<salt>$<hash>},
 * algoritmo {@code sha256Hex( sha256Hex(password) + salt )} (hex lowercase).
 */
public final class AuthMeSha256Verifier implements LegacyVerifier {

    @Override
    public boolean matches(String stored) {
        return stored != null && stored.startsWith("$SHA$");
    }

    @Override
    public boolean verify(char[] password, String stored) {
        String[] parts = stored.split("\\$"); // ["","SHA",salt,hash]
        if (parts.length != 4 || parts[2].isEmpty() || parts[3].isEmpty()) {
            return false;
        }
        String pw = new String(password);
        try {
            String inner = HexDigest.hexHash("SHA-256", pw);
            String computed = HexDigest.hexHash("SHA-256", inner + parts[2]);
            return MessageDigest.isEqual(
                    computed.getBytes(StandardCharsets.UTF_8),
                    parts[3].getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Override
    public String id() {
        return "authme-sha256";
    }
}
