package com.yastro.login.proxy;

import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.yastro.login.proxy.api.event.ArcherLoginEvent;
import com.yastro.login.proxy.api.event.ArcherPreLoginEvent;
import com.yastro.login.proxy.api.event.ArcherRegisterEvent;
import com.yastro.login.proxy.api.event.LoginType;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Ponte fina entre o fluxo de auth e o EventManager do Velocity. Centraliza o disparo
 * dos eventos públicos ({@code api.event.*}), o resto do código não fala com o
 * EventManager direto. Glue interno (não faz parte da API pública).
 */
final class AuthEvents {

    /**
     * Teto de espera do veto bloqueante. O pool de auth é pequeno (≈2 threads); sem teto,
     * um listener de 3º lento/pendurado seguraria a thread indefinidamente e estrangularia
     * o /login de todos (starvation/DoS). Estourou o prazo -> fail-open (permite) e segue.
     */
    private static final long VETO_TIMEOUT_SECONDS = 5;

    private final ProxyServer server;
    private final Logger logger;

    AuthEvents(ProxyServer server, Logger logger) {
        this.server = server;
        this.logger = logger;
    }

    /**
     * Dispara o pré-login e AGUARDA (bloqueante) o veredito. Chamar SOMENTE fora da thread
     * de evento do Velocity (ex.: pool de auth). Devolve o evento já processado (nunca null)
     * para o caller ler {@code getResult()}.
     *
     * <p>Falha-ABERTO: se o dispatch lançar/for interrompido, devolve o evento com o
     * resultado padrão ({@code allowed}) e loga, a auth primária já passou; um listener de
     * terceiro quebrado não deve trancar todos fora.
     */
    ArcherPreLoginEvent firePreLoginBlocking(Player player, LoginType type) {
        ArcherPreLoginEvent ev = new ArcherPreLoginEvent(player, type);
        try {
            return server.getEventManager().fire(ev).get(VETO_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            // Listener lento: paramos de esperar e liberamos a thread do pool de auth (o
            // listener segue rodando no executor de eventos do Velocity, não no nosso pool).
            logger.warn("ArcherPreLoginEvent excedeu {}s para {}, fail-open (permite). "
                    + "Um listener de terceiro está lento/pendurado.",
                    VETO_TIMEOUT_SECONDS, player.getUsername());
            return ev;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("ArcherPreLoginEvent interrompido para {}, fail-open (permite).",
                    player.getUsername());
            return ev; // result segue allowed (padrão)
        } catch (Exception e) {
            logger.warn("ArcherPreLoginEvent falhou para {}, fail-open (permite).",
                    player.getUsername(), e);
            return ev;
        }
    }

    /** Pré-login ASSÍNCRONO (caminho premium): o caller reage no {@code thenAccept}. */
    CompletableFuture<ArcherPreLoginEvent> firePreLoginAsync(Player player, LoginType type) {
        return server.getEventManager().fire(new ArcherPreLoginEvent(player, type));
    }

    /** Notificação de login bem-sucedido (fire-and-forget). Disparada PÓS-sucesso (jogador já
     * autenticado e no lobby); uma exceção de dispatch é só logada, nunca reverte a auth. */
    void fireLogin(Player player, LoginType type) {
        try {
            server.getEventManager().fireAndForget(new ArcherLoginEvent(player, type));
        } catch (Exception e) {
            logger.warn("Falha ao disparar ArcherLoginEvent para {} (login já efetivado).",
                    player.getUsername(), e);
        }
    }

    /** Notificação de registro bem-sucedido (fire-and-forget). Mesma garantia do {@link #fireLogin}. */
    void fireRegister(Player player) {
        try {
            server.getEventManager().fireAndForget(new ArcherRegisterEvent(player));
        } catch (Exception e) {
            logger.warn("Falha ao disparar ArcherRegisterEvent para {} (registro já efetivado).",
                    player.getUsername(), e);
        }
    }

    /** Motivo de desconexão de um pré-login negado, ou um padrão se o plugin não deu um. */
    static Component denyReason(ArcherPreLoginEvent ev) {
        ResultedEvent.ComponentResult r = ev.getResult();
        return r.getReasonComponent().orElseGet(
                () -> Component.text("Seu login foi bloqueado."));
    }
}
