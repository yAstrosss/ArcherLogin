package com.yastro.login.proxy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SensitiveCommandFilterTest {

    @Test
    void masksLoginArgsKeepingTheKeyword() {
        String masked = SensitiveCommandFilter.maskedOrNull("login SuperSecret123");
        assertNotNull(masked);
        assertTrue(masked.startsWith("login "), "keyword preservado");
        assertFalse(masked.contains("SuperSecret123"), "senha não pode sobrar");
        assertTrue(masked.length() - "login ".length() >= 5, "máscara tem corpo");
    }

    @Test
    void masksEachSensitiveCommandWithArgs() {
        for (String cmd : new String[]{
                "login p", "l p", "register p p", "reg p p"}) {
            assertNotNull(SensitiveCommandFilter.maskedOrNull(cmd), cmd + " deve mascarar");
        }
    }

    @Test
    void caseInsensitiveOnKeyword() {
        String masked = SensitiveCommandFilter.maskedOrNull("LOGIN secret");
        assertNotNull(masked);
        assertTrue(masked.startsWith("login "));
    }

    @Test
    void doesNotTouchNonSensitiveCommands() {
        assertNull(SensitiveCommandFilter.maskedOrNull("say ola pessoal"));
        assertNull(SensitiveCommandFilter.maskedOrNull("spawn"));
        assertNull(SensitiveCommandFilter.maskedOrNull("msg amigo minha senha é x"));
        // email/recuperar/trocarsenha são comandos reais do proxy (executam aqui), NÃO mascarar.
        assertNull(SensitiveCommandFilter.maskedOrNull("email alguem@gmail.com"));
        assertNull(SensitiveCommandFilter.maskedOrNull("recuperar 123456 novaSenha"));
        assertNull(SensitiveCommandFilter.maskedOrNull("trocarsenha velha nova"));
    }

    @Test
    void noArgsNothingToMask() {
        assertNull(SensitiveCommandFilter.maskedOrNull("login"));
        assertNull(SensitiveCommandFilter.maskedOrNull("register"));
        assertNull(SensitiveCommandFilter.maskedOrNull(""));
        assertNull(SensitiveCommandFilter.maskedOrNull(null));
    }
}
