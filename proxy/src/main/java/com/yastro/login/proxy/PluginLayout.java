package com.yastro.login.proxy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

/**
 * Layout de arquivos do plugin. Mantém na raiz só o que o dono edita
 * ({@code config.properties} e {@code messages.yml}) e empurra o resto pra subpastas:
 * o banco e o registro premium pra {@code database/}, os logs forenses pra {@code logs/}.
 *
 * <p>Na primeira execução da versão nova, migra o layout antigo (tudo solto na raiz)
 * sem perder dado: move os arquivos só se o destino ainda não existe.
 */
public final class PluginLayout {

    private final Path root;
    private final Path databaseDir;
    private final Path logsDir;

    private PluginLayout(Path root, Path databaseDir, Path logsDir) {
        this.root = root;
        this.databaseDir = databaseDir;
        this.logsDir = logsDir;
    }

    /** Cria os subdiretórios e migra os arquivos do layout antigo. Best-effort: nunca lança
     * (uma falha de E/S aqui não pode derrubar o boot do proxy; cai no mesmo modo de falha de antes). */
    public static PluginLayout prepare(Path root) {
        Path databaseDir = root.resolve("database");
        Path logsDir = root.resolve("logs");
        try {
            Files.createDirectories(databaseDir);
            Files.createDirectories(logsDir);
        } catch (IOException ignored) {
            // sem as pastas, as escritas seguintes falham igual ao comportamento anterior
        }
        migrate(root, databaseDir, logsDir);
        return new PluginLayout(root, databaseDir, logsDir);
    }

    /** Move os arquivos internos do layout antigo (raiz) pras subpastas. Idempotente: roda em
     * todo boot mas só faz algo na primeira vez (move só se o destino ainda não existe). */
    private static void migrate(Path root, Path databaseDir, Path logsDir) {
        // banco (os 3 arquivos do SQLite em modo WAL) + registro premium -> database/.
        // Ordem importa: move -wal/-shm ANTES e accounts.db por ÚLTIMO. Assim, se o JVM cair
        // no meio da migração, ou tudo já migrou, ou o accounts.db continua na raiz junto do
        // seu -wal (estado antigo íntegro) — nunca um .db órfão sem o WAL committado ao lado.
        for (String name : List.of("accounts.db-wal", "accounts.db-shm", "accounts.db", "premium-names.txt")) {
            move(root.resolve(name), databaseDir.resolve(name));
        }
        // logs forenses do layout antigo -> logs/. Nome fora do prefixo "diagnostic-" pra não
        // entrar no glob de retenção por-boot (senão ocuparia um slot fixo e nunca seria podado).
        move(root.resolve("diagnostic.log"), logsDir.resolve("legacy-diagnostic.log"));
        move(root.resolve("diagnostic.log.1"), logsDir.resolve("legacy-diagnostic.log.1"));
    }

    private static void move(Path from, Path to) {
        if (!Files.exists(from) || Files.exists(to)) {
            return;
        }
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicFailed) {
            try {
                Files.move(from, to);
            } catch (IOException ignored) {
                // best-effort: se não migrar, o arquivo antigo fica na raiz (não some, sem perda)
            }
        }
    }

    public Path root() {
        return root;
    }

    public Path databaseDir() {
        return databaseDir;
    }

    public Path logsDir() {
        return logsDir;
    }
}
