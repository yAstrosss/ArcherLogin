package com.yastro.login.authcore.hash.legacy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** AuthMe MD5 (unsalted, legado). Hash cru = 32 hex lowercase, sem prefixo. */
public final class AuthMeMd5Verifier implements LegacyVerifier {

    @Override
    public boolean matches(String stored) {
        return isHex(stored, 32);
    }

    @Override
    public boolean verify(char[] password, String stored) {
        if (stored == null) {
            return false;
        }
        try {
            String computed = HexDigest.hexHash("MD5", new String(password));
            return MessageDigest.isEqual(
                    computed.getBytes(StandardCharsets.UTF_8),
                    stored.toLowerCase().getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Override
    public String id() {
        return "authme-md5";
    }

    static boolean isHex(String s, int len) {
        if (s == null || s.length() != len) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            char c = Character.toLowerCase(s.charAt(i));
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) {
                return false;
            }
        }
        return true;
    }
}
