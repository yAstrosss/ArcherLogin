package com.yastro.login.authcore.hash;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHasherTest {

    // Parâmetros pequenos para o teste rodar rápido.
    private final PasswordHasher hasher = new PasswordHasher(8192, 1, 1);

    @Test
    void argon2RoundTrip() {
        String hash = hasher.hash("senhaForte123".toCharArray());
        assertTrue(hash.startsWith("$argon2id$v=19$m=8192,t=1,p=1$"), hash);
        assertTrue(hasher.verify("senhaForte123".toCharArray(), hash));
        assertFalse(hasher.verify("senhaErrada".toCharArray(), hash));
    }

    @Test
    void needsRehashOnlyWhenParamsDiffer() {
        String hash = hasher.hash("abc12345".toCharArray());
        assertFalse(hasher.needsRehash(hash));
        PasswordHasher stronger = new PasswordHasher(16384, 2, 1);
        assertTrue(stronger.needsRehash(hash));
    }

    @Test
    void verifiesImportedBcryptAndFlagsRehash() {
        String bcrypt = BCrypt.withDefaults().hashToString(4, "legado123".toCharArray());
        assertTrue(hasher.verify("legado123".toCharArray(), bcrypt));
        assertFalse(hasher.verify("outra".toCharArray(), bcrypt));
        assertTrue(hasher.needsRehash(bcrypt), "bcrypt deve ser migrado para Argon2id");
    }

    @Test
    void unknownFormatNeverAuthenticates() {
        assertFalse(hasher.verify("x".toCharArray(), "texto-puro-nao-hash"));
        assertFalse(hasher.verify("x".toCharArray(), ""));
        assertFalse(hasher.verify("x".toCharArray(), null));
    }

    @Test
    void algorithmDetection() {
        String argon = hasher.hash("abc12345".toCharArray());
        String bcrypt = BCrypt.withDefaults().hashToString(4, "abc12345".toCharArray());
        assertEquals("argon2id", PasswordHasher.algorithmOf(argon));
        assertEquals("bcrypt", PasswordHasher.algorithmOf(bcrypt));
        assertEquals("desconhecido", PasswordHasher.algorithmOf("???"));
    }

    @Test
    void differentSaltsProduceDifferentHashes() {
        String a = hasher.hash("mesmaSenha".toCharArray());
        String b = hasher.hash("mesmaSenha".toCharArray());
        assertFalse(a.equals(b), "salt aleatório deve gerar hashes distintos");
        assertTrue(hasher.verify("mesmaSenha".toCharArray(), a));
        assertTrue(hasher.verify("mesmaSenha".toCharArray(), b));
    }
}
