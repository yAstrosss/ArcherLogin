package com.yastro.login.authcore.config;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class MessagesTest {
    @Test
    void resolvesAndSubstitutes() {
        Messages m = Messages.fromMap(Map.of(
            "login.too-many", "&cAguarde %seconds%s.",
            "register.success", "&aRegistrado!"));
        assertEquals("&cAguarde 30s.", m.raw("login.too-many", "seconds", "30"));
        assertEquals("&aRegistrado!", m.raw("register.success"));
    }

    @Test
    void missingKeyReturnsKeyMarker() {
        Messages m = Messages.fromMap(Map.of());
        assertEquals("login.success", m.raw("login.success")); // fallback = própria chave
    }
}
