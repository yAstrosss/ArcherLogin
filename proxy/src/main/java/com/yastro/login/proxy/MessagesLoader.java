package com.yastro.login.proxy;

import com.yastro.login.authcore.config.Messages;
import org.slf4j.Logger;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Carrega o bundle de mensagens: o {@code messages.yml} empacotado é a base
 * COMPLETA (todas as chaves); o {@code messages.yml} do usuário, se existir,
 * sobrepõe chave a chave. O merge acontece ANTES de {@link Messages#fromMap}
 * (o fallback-de-chave-crua do Messages é só rede de segurança).
 */
public final class MessagesLoader {

    private static final String RESOURCE = "messages.yml";

    private MessagesLoader() {
    }

    /** Carrega defaults + merge do usuário (gera o arquivo do usuário se ausente). */
    public static Messages load(Path dataDirectory, Logger logger) {
        Map<String, String> merged = new LinkedHashMap<>(loadBundledDefaults());
        try {
            Files.createDirectories(dataDirectory);
            Path userFile = dataDirectory.resolve(RESOURCE);
            if (Files.exists(userFile)) {
                try (InputStream in = Files.newInputStream(userFile)) {
                    merged.putAll(flatten(parse(in)));
                }
            } else {
                try (InputStream res = resourceStream()) {
                    Files.copy(res, userFile);
                }
            }
        } catch (IOException e) {
            logger.warn("ArcherLogin: falha ao ler messages.yml do usuário; usando defaults.", e);
        }
        return fromFlat(merged);
    }

    /** Lê SÓ o bundle empacotado, já achatado em chaves com ponto. */
    public static Map<String, String> loadBundledDefaults() {
        try (InputStream res = resourceStream()) {
            return flatten(parse(res));
        } catch (IOException e) {
            throw new IllegalStateException("messages.yml empacotado ausente/ilegível", e);
        }
    }

    public static Messages fromFlat(Map<String, String> flat) {
        return Messages.fromMap(flat);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(InputStream in) {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Object loaded = yaml.load(new java.io.InputStreamReader(in, StandardCharsets.UTF_8));
        if (loaded instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        return new LinkedHashMap<>();
    }

    /** Achata mapas aninhados em chaves "a.b.c". Escalares viram String. */
    public static Map<String, String> flatten(Map<String, Object> nested) {
        Map<String, String> out = new LinkedHashMap<>();
        flattenInto("", nested, out);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void flattenInto(String prefix, Map<String, Object> node, Map<String, String> out) {
        for (Map.Entry<String, Object> e : node.entrySet()) {
            String key = prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey();
            Object v = e.getValue();
            if (v instanceof Map<?, ?> child) {
                flattenInto(key, (Map<String, Object>) child, out);
            } else if (v != null) {
                out.put(key, v.toString());
            }
        }
    }

    private static InputStream resourceStream() {
        InputStream in = MessagesLoader.class.getClassLoader().getResourceAsStream(RESOURCE);
        if (in == null) {
            throw new IllegalStateException("resource " + RESOURCE + " não encontrado no jar");
        }
        return in;
    }
}
