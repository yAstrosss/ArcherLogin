package com.yastro.login.authcore.config;

import java.util.HashMap;
import java.util.Map;

public final class Messages {
    private final Map<String, String> values;
    private Messages(Map<String, String> values) { this.values = values; }

    public static Messages fromMap(Map<String, String> flat) {
        return new Messages(new HashMap<>(flat));
    }

    public String raw(String key, String... repl) {
        String s = values.getOrDefault(key, key); // fallback: a própria chave (visível, não quebra)
        for (int i = 0; i + 1 < repl.length; i += 2) {
            s = s.replace("%" + repl[i] + "%", repl[i + 1]);
        }
        return s;
    }
}
