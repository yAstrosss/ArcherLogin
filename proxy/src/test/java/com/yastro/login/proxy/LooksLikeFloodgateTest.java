package com.yastro.login.proxy;

import com.yastro.login.proxy.bedrock.FloodgateNick;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Heurística de PreLogin (só o username disponível) pra detectar prefixo Floodgate. */
class LooksLikeFloodgateTest {

    @Test
    void detectsDefaultFloodgateDotPrefix() {
        assertTrue(FloodgateNick.looksLikeFloodgate(".Steve"));
    }

    @Test
    void rejectsNormalAlphanumericNick() {
        assertFalse(FloodgateNick.looksLikeFloodgate("Steve123"));
        assertFalse(FloodgateNick.looksLikeFloodgate("_underline_first"));
    }

    @Test
    void emptyUsernameIsNotFloodgate() {
        assertFalse(FloodgateNick.looksLikeFloodgate(""));
    }

    @Test
    void anyNonAlphanumericFirstCharCounts() {
        assertTrue(FloodgateNick.looksLikeFloodgate("*Alex"));
        assertTrue(FloodgateNick.looksLikeFloodgate("-Alex"));
    }
}
