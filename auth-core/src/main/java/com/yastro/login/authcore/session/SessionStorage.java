package com.yastro.login.authcore.session;

import java.sql.SQLException;
import java.util.Optional;

/** CRUD da tabela yastrologin_sessions. Uma sessão por conta (name_lower PK). */
public interface SessionStorage {
    void upsertSession(String nameLower, String ip, long expiresAtMillis) throws SQLException;
    Optional<Session> findSession(String nameLower) throws SQLException;
    void deleteSession(String nameLower) throws SQLException;
    void deleteExpiredSessions(long nowMillis) throws SQLException;
}
