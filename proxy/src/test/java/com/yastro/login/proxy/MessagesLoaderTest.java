package com.yastro.login.proxy;

import com.yastro.login.authcore.config.Messages;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessagesLoaderTest {

    @Test
    void flattenTurnsNestedMapsIntoDottedKeys() {
        Map<String, Object> login = new LinkedHashMap<>();
        login.put("usage", "use login");
        login.put("wrong", "errou");
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("prefix", "[y] ");
        root.put("login", login);

        Map<String, String> flat = MessagesLoader.flatten(root);

        assertEquals("[y] ", flat.get("prefix"));
        assertEquals("use login", flat.get("login.usage"));
        assertEquals("errou", flat.get("login.wrong"));
    }

    @Test
    void flattenCoercesNonStringScalarsToString() {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("n", 60);
        assertEquals("60", MessagesLoader.flatten(root).get("n"));
    }

    @Test
    void bundledDefaultsAreLoadableAndComplete() {
        // load() sem dataDir de usuário cai no resource empacotado.
        Messages m = MessagesLoader.fromFlat(MessagesLoader.loadBundledDefaults());
        assertTrue(m.raw("login.usage").contains("/login"));
        assertTrue(m.raw("register.success").length() > 0);
    }
}
