package com.yastro.login.authcore.auth;

import com.yastro.login.common.AccountKey;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Sessões de login provadas por um TOKEN aleatório (guardado como cookie no cliente
 * pelo chamador), NÃO por IP.
 *
 * <p>Antes a sessão validava só pelo IP, em IP compartilhado/CGNAT/VPN qualquer um
 * no mesmo NAT retomava a conta de um cracked sem senha (takeover). Agora a sessão
 * guarda um token de 32 bytes; só quem devolve o MESMO token (o mesmo cliente, via
 * cookie do Paper 1.20.5+) retoma. Um atacante no mesmo IP não tem o token.
 *
 * <p>Esta classe é PURA (sem Bukkit) para ser testável: {@link #open} gera/guarda o
 * token e o devolve; o chamador o grava no cliente. {@link #matches} valida o token
 * que o cliente apresentou. O I/O de cookie fica no chamador (AuthHandler/plugin).
 *
 * <ul>
 * <li>Em memória: restart do servidor limpa tudo (re-login).</li>
 * <li>Invalidada em logout e em troca de senha.</li>
 * </ul>
 */
public final class SessionManager implements SessionStore {

    private static final int TOKEN_LEN = 32;

    private record Session(byte[] token, long expiresAt) {
    }

    private final SecureRandom random = new SecureRandom();
    private volatile boolean enabled;
    private volatile long durationMillis;
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final AtomicInteger ops = new AtomicInteger();

    public SessionManager(boolean enabled, int durationMinutes) {
        reconfigure(enabled, durationMinutes);
    }

    /** Aplica novos parâmetros (no /reload) SEM apagar as sessões ativas. */
    public void reconfigure(boolean enabled, int durationMinutes) {
        // duration <= 0 desliga sessões (evita sessão permanente acidental).
        this.enabled = enabled && durationMinutes > 0;
        this.durationMillis = durationMinutes * 60_000L;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Abre/renova a sessão e devolve o token a guardar no cliente; {@code null} se
     * desligada. */
    public byte[] open(String name) {
        if (!enabled) {
            return null;
        }
        byte[] token = new byte[TOKEN_LEN];
        random.nextBytes(token);
        sessions.put(key(name), new Session(token, System.currentTimeMillis() + durationMillis));
        return token;
    }

    /** Confere, em tempo constante, se o token apresentado bate com a sessão ativa. */
    public boolean matches(String name, byte[] presentedToken) {
        if (!enabled || presentedToken == null) {
            return false;
        }
        maybeEvict();
        Session s = sessions.get(key(name));
        if (s == null) {
            return false;
        }
        if (System.currentTimeMillis() >= s.expiresAt()) {
            sessions.remove(key(name));
            return false;
        }
        return MessageDigest.isEqual(s.token(), presentedToken);
    }

    public void invalidate(String name) {
        sessions.remove(key(name));
    }

    private static String key(String name) {
        return AccountKey.normalize(name);
    }

    private void maybeEvict() {
        if (ops.incrementAndGet() % 500 != 0) {
            return;
        }
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(e -> now >= e.getValue().expiresAt());
    }
}
