package com.yastro.login.authcore.auth;

/**
 * Sessão de login provada por TOKEN (cookie no cliente), não por IP. Duas
 * implementações:
 *
 * <ul>
 * <li>{@link SessionManager}, em memória, por backend (standalone/SQLite).
 * Restart limpa tudo; um servidor só.</li>
 * <li>{@link SharedSessionStore}, persistida no banco compartilhado (MySQL).
 * Login vale em TODOS os backends da rede e sobrevive ao restart de um.</li>
 * </ul>
 *
 * <p>Contrato: {@link #open} gera/guarda o token e o devolve (o chamador grava no
 * cliente via cookie); {@link #matches} valida o token apresentado em tempo
 * constante. {@code open}/{@code invalidate} são NÃO-bloqueantes; {@code matches}
 * PODE bloquear (I/O no store compartilhado) e deve rodar fora da main thread.
 */
public interface SessionStore {

    /** Abre/renova a sessão e devolve o token a guardar no cliente; {@code null} se desligada. */
    byte[] open(String name);

    /** Confere, em tempo constante, se o token apresentado bate com a sessão ativa. */
    boolean matches(String name, byte[] presentedToken);

    /** Encerra a sessão (logout, troca de senha, ações admin). */
    void invalidate(String name);

    boolean isEnabled();

    /** Aplica novos parâmetros (no /reload) SEM apagar as sessões ativas. */
    void reconfigure(boolean enabled, int durationMinutes);
}
