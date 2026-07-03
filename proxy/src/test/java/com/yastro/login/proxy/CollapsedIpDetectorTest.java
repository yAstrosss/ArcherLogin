package com.yastro.login.proxy;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CollapsedIpDetectorTest {

    private static final long WINDOW = 60_000L;
    private static final long COOLDOWN = 300_000L;
    private static final int THRESHOLD = 8;

    private List<String> warns;
    private CollapsedIpDetector det;

    private CollapsedIpDetector make(Set<String> bypass) {
        warns = new ArrayList<>();
        return new CollapsedIpDetector(THRESHOLD, WINDOW, COOLDOWN, bypass, warns::add);
    }

    @Test
    void belowThresholdDoesNotWarn() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD - 1; i++) { // 7 nicks distintos
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertEquals(0, warns.size());
    }

    @Test
    void distinctNicksFromSameIpWarnOnce() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD; i++) { // 8 nicks distintos, mesmo IP
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertEquals(1, warns.size());
        assertTrue(warns.get(0).contains("5.5.5.5"), "msg deve citar o IP");
        // Mais nicks dentro do cooldown não refazem o aviso.
        det.observe("5.5.5.5", "userX", 2_000L);
        assertEquals(1, warns.size());
    }

    @Test
    void warnsAgainAfterCooldownAndWindow() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD; i++) {
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertEquals(1, warns.size());
        // t bem além do cooldown E da janela: entradas antigas evictadas, contador limpo.
        long later = 1_000L + COOLDOWN + WINDOW + 1;
        for (int i = 0; i < THRESHOLD; i++) {
            det.observe("5.5.5.5", "fresh" + i, later);
        }
        assertEquals(2, warns.size());
    }

    @Test
    void bypassIpNeverWarns() {
        det = make(Set.of("127.0.0.1"));
        for (int i = 0; i < THRESHOLD * 3; i++) {
            det.observe("127.0.0.1", "user" + i, 1_000L);
        }
        assertEquals(0, warns.size());
    }

    @Test
    void distinctIpsDoNotWarn() { // simula proxy-protocol ON: cada cliente com IP real diferente
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD * 4; i++) {
            det.observe("10.0.0." + i, "user" + i, 1_000L);
        }
        assertEquals(0, warns.size());
    }

    @Test
    void sameNickReconnectingDoesNotWarn() { // 1 jogador legítimo reconectando
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD * 3; i++) {
            det.observe("6.6.6.6", "bob", 1_000L + i);
        }
        assertEquals(0, warns.size());
    }

    @Test
    void isCollapsedFalseBelowThreshold() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD - 1; i++) { // 7 nicks distintos
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertFalse(det.isCollapsed("5.5.5.5", 1_000L));
    }

    @Test
    void isCollapsedTrueAtThreshold() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD; i++) { // 8 nicks distintos, mesmo IP
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertTrue(det.isCollapsed("5.5.5.5", 1_000L));
    }

    @Test
    void isCollapsedIndependentPerIp() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD; i++) {
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertTrue(det.isCollapsed("5.5.5.5", 1_000L));
        assertFalse(det.isCollapsed("9.9.9.9", 1_000L));
    }

    @Test
    void isCollapsedFalseAfterWindowExpires() {
        det = make(Set.of());
        for (int i = 0; i < THRESHOLD; i++) {
            det.observe("5.5.5.5", "user" + i, 1_000L);
        }
        assertTrue(det.isCollapsed("5.5.5.5", 1_000L));
        // Fora da janela: entradas expiraram do ponto de vista do "agora" consultado.
        assertFalse(det.isCollapsed("5.5.5.5", 1_000L + WINDOW + 1));
    }

    @Test
    void isCollapsedFalseForBypassIp() {
        det = make(Set.of("127.0.0.1"));
        for (int i = 0; i < THRESHOLD * 3; i++) {
            det.observe("127.0.0.1", "user" + i, 1_000L);
        }
        assertFalse(det.isCollapsed("127.0.0.1", 1_000L));
    }
}
