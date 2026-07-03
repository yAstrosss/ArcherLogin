package com.yastro.login.authcore.hash.legacy;

import java.util.List;

/** Registry ordenado dos verifiers legados suportados. */
public final class LegacyHashers {
    private LegacyHashers() {}

    /** Conjunto padrão (AuthMe family). Ordem = prioridade de detecção. */
    public static List<LegacyVerifier> defaultSet() {
        return List.of(
                new AuthMeSha256Verifier(),
                new AuthMePbkdf2Verifier()
                // B3 adiciona md5, sha512 aqui.
        );
    }

    /** Primeiro verifier cujo {@code matches} bate, ou null. */
    public static LegacyVerifier detect(List<LegacyVerifier> verifiers, String stored) {
        if (stored == null) {
            return null;
        }
        for (LegacyVerifier v : verifiers) {
            if (v.matches(stored)) {
                return v;
            }
        }
        return null;
    }
}
