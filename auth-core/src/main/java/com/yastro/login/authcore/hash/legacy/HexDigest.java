package com.yastro.login.authcore.hash.legacy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Utilitários de digest hex (lowercase) p/ os verifiers legados. */
final class HexDigest {
    private HexDigest() {}

    static byte[] digest(String algo, byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(algo);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algo + " indisponível", e);
        }
    }

    /** Digest de uma String (UTF-8) -> hex lowercase. */
    static String hexHash(String algo, String message) {
        byte[] d = digest(algo, message.getBytes(StandardCharsets.UTF_8));
        return hex(d);
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
