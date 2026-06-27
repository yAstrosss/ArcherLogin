package com.yastro.login.proxy;

import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import net.elytrium.limboapi.api.Limbo;
import net.elytrium.limboapi.api.LimboSessionHandler;
import net.elytrium.limboapi.api.player.LimboPlayer;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.title.Title;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Troca de senha SEGURA dentro do limbo virtual (fecha o H3). A senha atual e a nova
 * são digitadas como chat capturado pelo LimboAPI, NUNCA passam pelo dispatcher de
 * comando do Velocity (visível a command-loggers) nem pelo chat assinado do backend.
 *
 * <p>Fluxo de 2 passos: pede a senha ATUAL, depois a NOVA; ao terminar (sucesso ou
 * falha) o jogador autenticado volta pro lobby. Trabalho pesado vai pro executor do
 * {@link AuthService} (mesma rede de proteção do bounded + 1-in-flight).
 */
public final class ChangePasswordLimboHandler implements LimboSessionHandler {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private enum Stage { CURRENT, NEW }

    private final AuthService authService;
    private final LimboService limbo;
    private final Messages messages;
    private final ProxyConfig config;
    private final Logger logger;

    private LimboPlayer limboPlayer;
    private Player player;
    private volatile Stage stage = Stage.CURRENT; // CONC-3: visível entre onChat e onDisconnect
    private volatile char[] current; // CONC-3: senha atual (zerada após uso/disconnect)
    private final AtomicReference<ScheduledFuture<?>> idleReturn = new AtomicReference<>(); // CONC-2
    private final AtomicBoolean inFlight = new AtomicBoolean();
    private final AtomicBoolean finished = new AtomicBoolean(); // backToLobby idempotente (sucesso vs idle)

    public ChangePasswordLimboHandler(AuthService authService, LimboService limbo,
                                      Messages messages, ProxyConfig config, Logger logger) {
        this.authService = authService;
        this.limbo = limbo;
        this.messages = messages;
        this.config = config;
        this.logger = logger;
    }

    @Override
    public void onSpawn(Limbo server, LimboPlayer player) {
        this.limboPlayer = player;
        this.player = player.getProxyPlayer();
        player.getProxyPlayer().showTitle(Title.title(
                LEGACY.deserialize(messages.raw("title.changepass")),
                LEGACY.deserialize(messages.raw("title.changepass-sub")),
                Title.Times.times(Duration.ofMillis(200), Duration.ofSeconds(8), Duration.ofMillis(200))));
        send("changepass.enter-current");
        scheduleIdleReturn();
    }

    @Override
    public void onChat(String message) {
        if (message == null) {
            return;
        }
        String line = message.strip();
        if (line.isEmpty()) {
            return;
        }
        if (stage == Stage.CURRENT) {
            current = line.toCharArray();
            stage = Stage.NEW;
            send("changepass.enter-new");
            return;
        }
        // stage == NEW
        if (!inFlight.compareAndSet(false, true)) {
            send("login.processing");
            return;
        }
        char[] next = line.toCharArray();
        char[] cur = current; // a própria changePassword zera cur e next no finally dela
        current = null;
        String name = player.getUsername();
        String ip = ip();
        boolean queued = authService.trySubmit(() -> {
            try {
                AuthOutcome outcome = authService.changePassword(name, cur, next, ip);
                send(outcome.messageKey(), outcome.repl());
                cancelIdleReturn();
                backToLobby();
            } finally {
                inFlight.set(false);
            }
        });
        if (!queued) {
            Arrays.fill(cur, '\0');
            Arrays.fill(next, '\0');
            inFlight.set(false);
            send("error.busy");
        }
    }

    @Override
    public void onDisconnect() {
        cancelIdleReturn();
        char[] c = current;
        if (c != null) {
            Arrays.fill(c, '\0');
            current = null;
        }
    }

    /** Volta o jogador (autenticado) pro lobby. Roda na thread do executor; chamadas Velocity são thread-safe. */
    private void backToLobby() {
        if (!finished.compareAndSet(false, true)) {
            return; // idempotente, corrida entre a troca bem-sucedida e o idle-return
        }
        boolean moved;
        try {
            moved = limbo.sendToLobby(limboPlayer);
        } catch (RuntimeException e) {
            // não deixa preso no limbo, informa e desconecta (reconecta quando o lobby voltar).
            logger.warn("changepass: falha ao mover {} ao lobby: {}", player.getUsername(), e.toString());
            player.disconnect(LEGACY.deserialize(messages.raw("title.lobby-unavailable")));
            return;
        }
        if (!moved) {
            // lobby fora -> informa e desconecta em vez de deixar preso no limbo.
            logger.warn("changepass: lobby '{}' indisponível para {}.", config.lobbyServer, player.getUsername());
            player.disconnect(LEGACY.deserialize(messages.raw("title.lobby-unavailable")));
        }
    }

    private void scheduleIdleReturn() {
        int secs = config.limboTimeoutSeconds;
        if (secs <= 0) {
            return;
        }
        // Jogador autenticado: ao ficar ocioso, NÃO expulsa, só devolve pro lobby.
        ScheduledFuture<?> f = limboPlayer.getScheduledExecutor().schedule(() -> {
            send("login.timeout");
            backToLobby();
        }, secs, TimeUnit.SECONDS);
        ScheduledFuture<?> prev = idleReturn.getAndSet(f); // CONC-2: troca atômica
        if (prev != null) {
            prev.cancel(false);
        }
    }

    private void cancelIdleReturn() {
        ScheduledFuture<?> f = idleReturn.getAndSet(null); // CONC-2
        if (f != null) {
            f.cancel(false);
        }
    }

    private void send(String key, String... repl) {
        player.sendMessage(LEGACY.deserialize(messages.raw("prefix") + messages.raw(key, repl)));
    }

    private String ip() {
        if (player.getRemoteAddress() instanceof InetSocketAddress addr) {
            return addr.getAddress().getHostAddress();
        }
        return "unknown";
    }
}
