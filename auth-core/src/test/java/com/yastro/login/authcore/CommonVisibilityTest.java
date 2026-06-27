package com.yastro.login.authcore;

import com.yastro.login.common.MojangClient;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommonVisibilityTest {
    @Test
    void seesCommonModule() {
        assertTrue(MojangClient.VALID_NICK.matcher("Player_1").matches());
    }
}
