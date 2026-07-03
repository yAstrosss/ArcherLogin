package com.yastro.login.proxy.bedrock;

import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class NoopBedrockServiceTest {
    @Test
    void neverAvailableNeverBedrock() {
        BedrockService s = new NoopBedrockService();
        assertFalse(s.available());
        assertFalse(s.isBedrock(UUID.randomUUID()));
        assertTrue(s.username(UUID.randomUUID()).isEmpty());
    }
}
