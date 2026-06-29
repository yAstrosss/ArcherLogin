package com.yastro.login.authcore.storage;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Storage MySQL/MariaDB com pool de conexões (HikariCP). Indicado quando vários
 * servidores backend compartilham o mesmo banco de contas.
 */
public final class MySqlStorage extends JdbcStorage {

    private final HikariDataSource ds;

    private MySqlStorage(HikariDataSource ds) {
        this.ds = ds;
    }

    public static MySqlStorage open(String host, int port, String database,
                                    String user, String password, int poolSize) throws SQLException {
        HikariConfig hc = new HikariConfig();
        hc.setPoolName("ArcherLogin-SQL");
        // Driver MariaDB (puro Java) conecta tanto MariaDB quanto MySQL.
        hc.setJdbcUrl("jdbc:mariadb://" + host + ":" + port + "/" + database);
        hc.setUsername(user);
        hc.setPassword(password);
        hc.setMaximumPoolSize(Math.max(2, poolSize));
        // pool fixo (minIdle = maxPoolSize), mantém todas as conexões quentes, sem
        // latência de cold-connect no pico de logins (restart com muitos reconectando).
        hc.setMinimumIdle(hc.getMaximumPoolSize());
        hc.setMaxLifetime(1_800_000L); // 30 min
        hc.setConnectionTimeout(5_000L); // 5 s
        hc.addDataSourceProperty("cachePrepStmts", "true");
        hc.addDataSourceProperty("prepStmtCacheSize", "250");
        hc.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        HikariDataSource dataSource = new HikariDataSource(hc);
        MySqlStorage s = new MySqlStorage(dataSource);
        s.init();
        return s;
    }

    @Override
    protected <T> T exec(ConnFn<T> fn) throws SQLException {
        try (Connection c = ds.getConnection()) {
            return fn.apply(c);
        }
    }

    @Override
    protected void createSchema(Connection c) throws SQLException {
        String ddl = "CREATE TABLE IF NOT EXISTS " + TABLE + " ("
                + "name_lower VARCHAR(16) PRIMARY KEY,"
                + "name VARCHAR(16) NOT NULL,"
                + "uuid VARCHAR(36) NOT NULL,"
                + "password_hash VARCHAR(255) NOT NULL,"
                + "email VARCHAR(255),"
                + "reg_ip VARCHAR(45),"
                + "last_ip VARCHAR(45),"
                + "premium TINYINT NOT NULL DEFAULT 0,"
                + "registered_at BIGINT NOT NULL,"
                + "last_login BIGINT NOT NULL DEFAULT 0,"
                + "INDEX idx_regip (reg_ip)"
                + ") CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci";
        try (Statement st = c.createStatement()) {
            st.execute(ddl);
        }
    }

    @Override
    public void close() {
        ds.close();
    }
}
