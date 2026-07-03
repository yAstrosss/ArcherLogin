package com.yastro.login.authcore.storage;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Storage SQLite: uma única conexão serializada por um lock. Adequado a um
 * backend. Para vários backends compartilhando login, use MySQL/MariaDB.
 */
public final class SqliteStorage extends JdbcStorage {

    private final Connection connection;
    private final Object lock = new Object();

    private SqliteStorage(Connection connection) {
        this.connection = connection;
    }

    public static SqliteStorage open(Path databaseFile) throws SQLException {
        // Garante que o driver relocado seja carregado.
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException ignored) {
            // Em runtime relocado o nome muda; o DriverManager via SPI ainda acha.
        }
        Connection conn = DriverManager.getConnection("jdbc:sqlite:" + databaseFile);
        SqliteStorage s = new SqliteStorage(conn);
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA journal_mode=WAL");
            st.execute("PRAGMA foreign_keys=ON");
        }
        s.init();
        return s;
    }

    @Override
    protected <T> T exec(ConnFn<T> fn) throws SQLException {
        synchronized (lock) {
            return fn.apply(connection);
        }
    }

    @Override
    protected void createSchema(Connection c) throws SQLException {
        String ddl = "CREATE TABLE IF NOT EXISTS " + TABLE + " ("
                + "name_lower TEXT PRIMARY KEY,"
                + "name TEXT NOT NULL,"
                + "uuid TEXT NOT NULL,"
                + "password_hash TEXT NOT NULL,"
                + "email TEXT,"
                + "reg_ip TEXT,"
                + "last_ip TEXT,"
                + "premium INTEGER NOT NULL DEFAULT 0,"
                + "registered_at INTEGER NOT NULL,"
                + "last_login INTEGER NOT NULL DEFAULT 0,"
                + "bedrock INTEGER NOT NULL DEFAULT 0)";
        try (Statement st = c.createStatement()) {
            st.execute(ddl);
            st.execute("CREATE INDEX IF NOT EXISTS idx_" + TABLE + "_regip ON "
                    + TABLE + " (reg_ip)");
        }
        ensureBedrockColumn(c);
    }

    /** Migracao idempotente: adiciona a coluna bedrock em bancos criados antes da task A1. */
    private void ensureBedrockColumn(Connection c) throws SQLException {
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("PRAGMA table_info(" + TABLE + ")")) {
            boolean has = false;
            while (rs.next()) {
                if ("bedrock".equalsIgnoreCase(rs.getString("name"))) { has = true; break; }
            }
            if (!has) {
                try (Statement alt = c.createStatement()) {
                    alt.execute("ALTER TABLE " + TABLE + " ADD COLUMN bedrock INTEGER NOT NULL DEFAULT 0");
                }
            }
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            try {
                connection.close();
            } catch (SQLException ignored) {
            }
        }
    }
}
