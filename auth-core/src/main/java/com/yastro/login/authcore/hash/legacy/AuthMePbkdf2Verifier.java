package com.yastro.login.authcore.hash.legacy;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * AuthMe PBKDF2. Formato {@code pbkdf2_sha256$<iter>$<salt>$<HEX_UPPER>}.
 * PBKDF2 HMAC-SHA256; senha em UTF-8; salt = BYTES ASCII da string hex do salt;
 * dkLen = tamanho do hash decodificado; iterações lidas da string.
 */
public final class AuthMePbkdf2Verifier implements LegacyVerifier {

    @Override
    public boolean matches(String stored) {
        return stored != null && stored.startsWith("pbkdf2_sha256$");
    }

    @Override
    public boolean verify(char[] password, String stored) {
        if (stored == null) {
            return false;
        }
        String[] line = stored.split("\\$"); // ["pbkdf2_sha256", iter, salt, hexHash]
        if (line.length != 4) {
            return false;
        }
        final int iterations;
        try {
            iterations = Integer.parseInt(line[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        byte[] expected;
        try {
            expected = Hex.decode(line[3]);
        } catch (RuntimeException e) {
            return false;
        }
        byte[] pw = new String(password).getBytes(StandardCharsets.UTF_8);
        try {
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
            gen.init(pw, line[2].getBytes(StandardCharsets.US_ASCII), iterations);
            byte[] computed = ((KeyParameter) gen.generateDerivedMacParameters(expected.length * 8)).getKey();
            try {
                return MessageDigest.isEqual(computed, expected);
            } finally {
                Arrays.fill(computed, (byte) 0);
            }
        } catch (RuntimeException e) {
            return false;
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    @Override
    public String id() {
        return "authme-pbkdf2";
    }
}
