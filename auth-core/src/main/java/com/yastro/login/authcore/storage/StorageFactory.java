package com.yastro.login.authcore.storage;

import com.yastro.login.authcore.config.AuthConfig;

import java.nio.file.Path;

/**
 * Cria o {@link AccountStorage} conforme {@code database.type} da config.
 */
public final class StorageFactory {

    private StorageFactory() {
    }

    public static AccountStorage create(AuthConfig cfg, Path dataFolder) throws Exception {
        if ("mysql".equals(cfg.dbType) || "mariadb".equals(cfg.dbType)) {
            return MySqlStorage.open(
                    cfg.mysqlHost, cfg.mysqlPort, cfg.mysqlDatabase,
                    cfg.mysqlUser, cfg.mysqlPassword, cfg.mysqlPoolSize);
        }
        return SqliteStorage.open(dataFolder.resolve("accounts.db"));
    }
}
