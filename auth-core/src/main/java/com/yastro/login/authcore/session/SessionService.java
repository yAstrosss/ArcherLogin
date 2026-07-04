package com.yastro.login.authcore.session;

import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * Sessão persistente IP-based (só cracked). Cria no /login, valida no reconnect
 * (mesmo nick+IP, não expirada), revoga no /logout e em toda troca de senha.
 * storage nulo (banco fora) ou desligada -> tudo no-op / valida false. Nunca lança.
 */
public final class SessionService {

    private static final System.Logger LOG = System.getLogger("ArcherLogin-Session");

    private final SessionStorage storage; // pode ser null (banco fora)
    private final LongSupplier clock;
    private final boolean enabled;
    private final long ttlMillis;

    public SessionService(SessionStorage storage, LongSupplier clock, boolean enabled, long ttlMinutes) {
        this.storage = storage;
        this.clock = clock;
        this.enabled = enabled;
        this.ttlMillis = ttlMinutes * 60_000L;
    }

    /** Cria/renova a sessão do nick a partir do IP. Poda expiradas de carona. */
    public void create(String nameLower, String ip) {
        if (!enabled || storage == null || ip == null) {
            return;
        }
        long now = clock.getAsLong();
        try {
            storage.deleteExpiredSessions(now);
            storage.upsertSession(nameLower, ip, now + ttlMillis);
        } catch (Exception ignored) {
            // sessão é conveniência; falha não bloqueia o login
        }
    }

    /** True se existe sessão não-expirada do nick com o MESMO IP. */
    public boolean validate(String nameLower, String ip) {
        if (!enabled || storage == null || ip == null) {
            return false;
        }
        try {
            Optional<Session> s = storage.findSession(nameLower);
            if (s.isEmpty()) {
                return false;
            }
            Session sess = s.get();
            if (sess.expiresAtMillis() <= clock.getAsLong()) {
                storage.deleteSession(nameLower); // limpa a expirada
                return false;
            }
            return ip.equals(sess.ip());
        } catch (Exception e) {
            return false; // falha de storage nunca vira auto-login
        }
    }

    /** Apaga a sessão do nick (logout / troca de senha). */
    public void revoke(String nameLower) {
        if (storage == null) {
            return;
        }
        try {
            storage.deleteSession(nameLower);
        } catch (Exception e) {
            // NÃO engolir em silêncio: se o DELETE falhar (pool saturado / DB instável) a sessão
            // SOBREVIVE ao /logout e ainda auto-loga até o TTL. Operador precisa enxergar.
            LOG.log(System.Logger.Level.WARNING,
                    "revoke de sessão FALHOU para " + nameLower
                            + ": a sessão pode sobreviver até o TTL (logout não removeu do banco).", e);
        }
    }
}
