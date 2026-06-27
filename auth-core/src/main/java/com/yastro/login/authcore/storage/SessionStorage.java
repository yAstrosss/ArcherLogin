package com.yastro.login.authcore.storage;

/**
 * Persistência de sessões de login no banco compartilhado (usado por
 * {@code SharedSessionStore} no modo MySQL/multi-backend). Guarda apenas o
 * <b>HASH</b> do token (nunca o token cru): vazamento do banco não entrega
 * sessões vivas. Chaveado por {@code name_lower}, o mesmo identificador das
 * contas, consistente entre todos os backends.
 *
 * <p>Todas as chamadas são SÍNCRONAS e devem rodar FORA da main thread.
 */
public interface SessionStorage {

    /** Cria ou substitui a sessão da chave com o hash e a expiração dados. */
    void upsertSession(String key, byte[] tokenHash, long expiresAt) throws Exception;

    /** Hash da sessão ativa (não expirada em {@code now}) ou {@code null}. */
    byte[] findSessionHash(String key, long now) throws Exception;

    /** Remove a sessão da chave (logout/invalidação). */
    void removeSession(String key) throws Exception;

    /** Apaga todas as sessões expiradas em {@code now} (limpeza periódica). */
    void purgeSessions(long now) throws Exception;
}
