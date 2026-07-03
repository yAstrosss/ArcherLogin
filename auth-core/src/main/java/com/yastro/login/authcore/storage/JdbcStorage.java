package com.yastro.login.authcore.storage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import com.yastro.login.common.AccountKey;

/**
 * Implementação JDBC compartilhada por SQLite e MySQL. Toda query usa
 * {@link PreparedStatement} (sem SQL injection). As subclasses fornecem a conexão
 * ({@link #exec}) e o DDL específico do dialeto ({@link #createSchema}).
 */
public abstract class JdbcStorage implements AccountStorage,
        com.yastro.login.authcore.session.SessionStorage {

    protected static final String TABLE = "yastrologin_accounts";
    protected static final String SESSIONS = "yastrologin_sessions";

    @FunctionalInterface
    protected interface ConnFn<T> {
        T apply(Connection c) throws SQLException;
    }

    /** Empresta uma conexão para a função e devolve/fecha conforme a impl. */
    protected abstract <T> T exec(ConnFn<T> fn) throws SQLException;

    /** DDL específico do dialeto (tipos diferem entre SQLite e MySQL). */
    protected abstract void createSchema(Connection c) throws SQLException;

    protected void init() throws SQLException {
        exec(c -> {
            createSchema(c);
            return null;
        });
    }

    @Override
    public boolean isRegistered(String name) throws SQLException {
        String key = AccountKey.normalize(name);
        return exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT 1 FROM " + TABLE + " WHERE name_lower = ?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        });
    }

    @Override
    public Optional<Account> find(String name) throws SQLException {
        String key = AccountKey.normalize(name);
        return exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT name, uuid, password_hash, email, reg_ip, last_ip, premium, "
                            + "registered_at, last_login, bedrock FROM " + TABLE + " WHERE name_lower = ?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return Optional.empty();
                    }
                    return Optional.of(new Account(
                            rs.getString("name"),
                            rs.getString("uuid"),
                            rs.getString("password_hash"),
                            rs.getString("email"),
                            rs.getString("reg_ip"),
                            rs.getString("last_ip"),
                            rs.getInt("premium") != 0,
                            rs.getLong("registered_at"),
                            rs.getLong("last_login"),
                            rs.getInt("bedrock") != 0));
                }
            }
        });
    }

    @Override
    public void register(Account a) throws SQLException {
        exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO " + TABLE + " (name_lower, name, uuid, password_hash, email, "
                            + "reg_ip, last_ip, premium, registered_at, last_login, bedrock) "
                            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                ps.setString(1, AccountKey.normalize(a.name()));
                ps.setString(2, a.name());
                ps.setString(3, a.uuid());
                ps.setString(4, a.passwordHash());
                ps.setString(5, a.email());
                ps.setString(6, a.regIp());
                ps.setString(7, a.lastIp());
                ps.setInt(8, a.premium() ? 1 : 0);
                ps.setLong(9, a.registeredAt());
                ps.setLong(10, a.lastLogin());
                ps.setInt(11, a.bedrock() ? 1 : 0);
                ps.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public void updatePassword(String name, String newHash) throws SQLException {
        String key = AccountKey.normalize(name);
        exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET password_hash = ? WHERE name_lower = ?")) {
                ps.setString(1, newHash);
                ps.setString(2, key);
                ps.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public void touchLogin(String name, String ip, long when) throws SQLException {
        String key = AccountKey.normalize(name);
        exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET last_ip = ?, last_login = ? WHERE name_lower = ?")) {
                ps.setString(1, ip);
                ps.setLong(2, when);
                ps.setString(3, key);
                ps.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public void setEmail(String name, String email) throws SQLException {
        String key = AccountKey.normalize(name);
        exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE " + TABLE + " SET email = ? WHERE name_lower = ?")) {
                ps.setString(1, email);
                ps.setString(2, key);
                ps.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public int countByRegIp(String ip) throws SQLException {
        if (ip == null) {
            return 0;
        }
        return exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT COUNT(*) FROM " + TABLE + " WHERE reg_ip = ?")) {
                ps.setString(1, ip);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }

    @Override
    public void upsertSession(String nameLower, String ip, long expiresAtMillis) throws SQLException {
        exec(c -> {
            // delete-then-insert = upsert portável (SQLite e MySQL) sem sintaxe específica de dialeto
            try (PreparedStatement del = c.prepareStatement(
                    "DELETE FROM " + SESSIONS + " WHERE name_lower = ?")) {
                del.setString(1, nameLower);
                del.executeUpdate();
            }
            try (PreparedStatement ins = c.prepareStatement(
                    "INSERT INTO " + SESSIONS + " (name_lower, ip, expires_at) VALUES (?, ?, ?)")) {
                ins.setString(1, nameLower);
                ins.setString(2, ip);
                ins.setLong(3, expiresAtMillis);
                ins.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public java.util.Optional<com.yastro.login.authcore.session.Session> findSession(String nameLower)
            throws SQLException {
        return exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT ip, expires_at FROM " + SESSIONS + " WHERE name_lower = ?")) {
                ps.setString(1, nameLower);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return java.util.Optional.empty();
                    }
                    return java.util.Optional.of(new com.yastro.login.authcore.session.Session(
                            nameLower, rs.getString("ip"), rs.getLong("expires_at")));
                }
            }
        });
    }

    @Override
    public void deleteSession(String nameLower) throws SQLException {
        exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "DELETE FROM " + SESSIONS + " WHERE name_lower = ?")) {
                ps.setString(1, nameLower);
                ps.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public void deleteExpiredSessions(long nowMillis) throws SQLException {
        exec(c -> {
            try (PreparedStatement ps = c.prepareStatement(
                    "DELETE FROM " + SESSIONS + " WHERE expires_at <= ?")) {
                ps.setLong(1, nowMillis);
                ps.executeUpdate();
            }
            return null;
        });
    }
}
