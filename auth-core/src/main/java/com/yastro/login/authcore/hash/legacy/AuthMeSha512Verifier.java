package com.yastro.login.authcore.hash.legacy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** AuthMe SHA512 (unsalted, legado). Hash cru = 128 hex lowercase, sem prefixo. */
public final class AuthMeSha512Verifier implements LegacyVerifier {

    @Override
    public boolean matches(String stored) {
        return AuthMeMd5Verifier.isHex(stored, 128);
    }

    @Override
    public boolean verify(char[] password, String stored) {
        if (stored == null) {
            return false;
        }
        try {
            String computed = HexDigest.hexHash("SHA-512", new String(password));
            return MessageDigest.isEqual(
                    computed.getBytes(StandardCharsets.UTF_8),
                    stored.toLowerCase().getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Override
    public String id() {
        return "authme-sha512";
    }
}
