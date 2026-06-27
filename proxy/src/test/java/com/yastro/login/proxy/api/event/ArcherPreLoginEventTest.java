package com.yastro.login.proxy.api.event;

import com.velocitypowered.api.event.ResultedEvent.ComponentResult;
import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testa só a lógica de resultado do evento (POJO), sem servidor Velocity. O {@code Player}
 * é null de propósito: getResult/setResult não tocam nele. O comportamento em runtime
 * (disparo/veto/desconexão) é coberto pelo TESTAR MANUAL no relatório (precisa de proxy vivo).
 */
class ArcherPreLoginEventTest {

    @Test
    void defaultResult_isAllowed() {
        ArcherPreLoginEvent ev = new ArcherPreLoginEvent(null, LoginType.PASSWORD);
        assertTrue(ev.getResult().isAllowed());
    }

    @Test
    void denied_carriesReason_andBlocks() {
        ArcherPreLoginEvent ev = new ArcherPreLoginEvent(null, LoginType.PREMIUM);
        ev.setResult(ComponentResult.denied(Component.text("manutencao")));
        assertFalse(ev.getResult().isAllowed());
        assertTrue(ev.getResult().getReasonComponent().isPresent());
        assertEquals("manutencao",
                ((net.kyori.adventure.text.TextComponent) ev.getResult().getReasonComponent().get()).content());
    }

    @Test
    void setResult_null_throws() {
        ArcherPreLoginEvent ev = new ArcherPreLoginEvent(null, LoginType.PASSWORD);
        assertThrows(NullPointerException.class, () -> ev.setResult(null));
    }

    @Test
    void type_isCarried() {
        assertEquals(LoginType.PREMIUM, new ArcherPreLoginEvent(null, LoginType.PREMIUM).getType());
        assertEquals(LoginType.PASSWORD, new ArcherPreLoginEvent(null, LoginType.PASSWORD).getType());
    }
}
