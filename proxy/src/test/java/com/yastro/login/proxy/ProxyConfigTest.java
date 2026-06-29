package com.yastro.login.proxy;

import com.yastro.login.authcore.config.AuthConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ProxyConfigTest {

    @Test
    void writesAndReloadsDefaults(@TempDir Path dir) {
        ProxyConfig first = ProxyConfig.load(dir); // cria o arquivo com defaults
        ProxyConfig second = ProxyConfig.load(dir); // relê
        assertEquals("lobby", second.lobbyServer);
        assertTrue(second.unknownPolicyDeny);
        assertFalse(second.allowCrackedOnPremiumNicks);
    }

    @Test
    void seededAuthDefaultsFlowToAuthConfig(@TempDir Path dir) {
        ProxyConfig.load(dir); // grava defaults (inclui os knobs do grupo ②)
        AuthConfig ac = ProxyConfig.load(dir).authConfig();
        assertEquals(19456, ac.argonMemoryKib);
        assertEquals(2, ac.argonIterations);
        assertEquals(1, ac.argonParallelism);
        assertEquals(8, ac.minPassword);
        assertEquals(5, ac.maxAttempts);
        assertEquals(300, ac.lockoutSeconds);
        assertEquals(10, ac.accountMaxAttempts);
    }

    @Test
    void overridesAuthKnobsFromProperties(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("config.properties");
        java.nio.file.Files.writeString(file,
            "hash-argon2-memory-kib=32768\npassword-min-length=12\n"
            + "bruteforce-max-attempts=3\n");
        AuthConfig ac = ProxyConfig.load(dir).authConfig();
        assertEquals(32768, ac.argonMemoryKib);
        assertEquals(12, ac.minPassword);
        assertEquals(3, ac.maxAttempts);
    }

    @Test
    void buildsAuthConfigFromDbKeys(@TempDir Path dir) {
        ProxyConfig cfg = ProxyConfig.load(dir);
        AuthConfig ac = cfg.authConfig();
        assertEquals("sqlite", ac.dbType); // default do AuthConfig quando ausente
        assertNotNull(ac);
    }

    @Test
    void seedsDiagnosticDefaults(@TempDir Path dir) {
        ProxyConfig.load(dir);
        ProxyConfig cfg = ProxyConfig.load(dir);
        assertTrue(cfg.diagnosticEnabled);
        assertEquals(100, cfg.diagnosticFloodPerMin);
    }

    @Test
    void seedsUiToggles(@TempDir Path dir) {
        ProxyConfig.load(dir);
        ProxyConfig cfg = ProxyConfig.load(dir);
        assertTrue(cfg.uiTitle);
        assertTrue(cfg.uiActionBar);
        assertTrue(cfg.uiSound);
    }

    @Test
    void seedsAndParsesIpLimit(@TempDir Path dir) {
        ProxyConfig.load(dir); // grava defaults
        ProxyConfig cfg = ProxyConfig.load(dir);
        IpLimitPolicy p = cfg.ipLimitPolicy();
        assertTrue(p.enabled());
        assertEquals(3, p.max());
        assertTrue(p.bypass().contains("127.0.0.1"));
    }

    @Test
    void passesMysqlThroughToAuthConfig(@TempDir Path dir) throws Exception {
        // grava um config.properties com mysql e relê
        Path file = dir.resolve("config.properties");
        java.nio.file.Files.writeString(file,
            "db-type=mysql\ndb-host=db.example\ndb-port=3307\ndb-name=net\ndb-user=u\ndb-password=p\n");
        ProxyConfig cfg = ProxyConfig.load(dir);
        AuthConfig ac = cfg.authConfig();
        assertEquals("mysql", ac.dbType);
        assertEquals("db.example", ac.mysqlHost);
        assertEquals(3307, ac.mysqlPort);
        assertEquals("net", ac.mysqlDatabase);
    }

    @Test
    void preservesNonAsciiValueAcrossReboots(@TempDir Path dir) throws Exception {
        // valor com acento (senha/remetente): write UTF-8 + read UTF-8 tem que casar e ser estável
        Path file = dir.resolve("config.properties");
        java.nio.file.Files.writeString(file,
            "db-password=senhâ123\nemail-smtp-from=Açaí Server\n",
            java.nio.charset.StandardCharsets.UTF_8);
        ProxyConfig.load(dir);            // 1º boot: renderiza o template (reescreve)
        ProxyConfig.load(dir);            // 2º boot: relê o que escreveu
        java.util.Properties after = new java.util.Properties();
        try (var r = java.nio.file.Files.newBufferedReader(file, java.nio.charset.StandardCharsets.UTF_8)) {
            after.load(r);
        }
        assertEquals("senhâ123", after.getProperty("db-password"));
        assertEquals("Açaí Server", after.getProperty("email-smtp-from"));
    }

    @Test
    void mergesMissingKeysIntoExistingConfig(@TempDir Path dir) throws Exception {
        // config "antigo": tem um valor custom mas faltam as chaves novas
        Path file = dir.resolve("config.properties");
        java.nio.file.Files.writeString(file, "lobby-server=meulobby\nip-limit-max-accounts=7\n");

        ProxyConfig cfg = ProxyConfig.load(dir); // deve mesclar as chaves faltantes no arquivo

        // valores do owner preservados (não sobrescritos pelos defaults)
        assertEquals("meulobby", cfg.lobbyServer);
        assertEquals(7, cfg.ipLimitMax);

        // chaves novas agora existem no arquivo em disco (owner consegue editá-las)
        java.util.Properties after = new java.util.Properties();
        try (var in = java.nio.file.Files.newInputStream(file)) {
            after.load(in);
        }
        assertTrue(after.containsKey("diagnostic-enabled"));
        assertTrue(after.containsKey("ui-title"));
        assertTrue(after.containsKey("auth-queue-capacity"));
        assertEquals("7", after.getProperty("ip-limit-max-accounts")); // custom intacto
    }
}
