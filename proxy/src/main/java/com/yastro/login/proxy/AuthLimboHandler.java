package com.yastro.login.proxy;

import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import com.yastro.login.authcore.storage.AccountStorage;
import com.yastro.login.proxy.api.event.ArcherPreLoginEvent;
import com.yastro.login.proxy.api.event.LoginType;
import net.elytrium.limboapi.api.Limbo;
import net.elytrium.limboapi.api.LimboSessionHandler;
import net.elytrium.limboapi.api.player.LimboPlayer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.title.Title;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Sessão do jogador não-autenticado no limbo. {@code onChat} captura /login e
 * /register (LimboAPI não tem onCommand; a senha não passa pelo pipeline de
 * comando/chat do Velocity nem de backend). Trabalho pesado vai pro executor do
 * {@link AuthService}; a resposta volta como {@link AuthOutcome}.
 */
public final class AuthLimboHandler implements LimboSessionHandler {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthService authService;
    private final LimboService limbo;
    private final AuthState authState;
    private final Messages messages;
    private final AccountStorage storage;
    private final ProxyConfig config;
    private final Logger logger;
    private final EmailFlow emailFlow;
    private final DiagnosticLog diag;
    private final AuthEvents authEvents;

    private LimboPlayer limboPlayer;
    private Player player;
    private final AtomicReference<ScheduledFuture<?>> idleKick = new AtomicReference<>(); // CONC-2
    /** Garante no máx. 1 auth em voo por conexão: corta o spam de /login antes do pool (C1). */
    private final AtomicBoolean authInFlight = new AtomicBoolean();

    public AuthLimboHandler(AuthService authService, LimboService limbo, AuthState authState,
                            Messages messages, AccountStorage storage, ProxyConfig config, Logger logger,
                            EmailFlow emailFlow, DiagnosticLog diag, AuthEvents authEvents) {
        this.authService = authService;
        this.limbo = limbo;
        this.authState = authState;
        this.messages = messages;
        this.storage = storage;
        this.config = config;
        this.logger = logger;
        this.emailFlow = emailFlow;
        this.diag = diag;
        this.authEvents = authEvents;
    }

    @Override
    public void onSpawn(Limbo server, LimboPlayer player) {
        this.limboPlayer = player;
        this.player = player.getProxyPlayer();
        // O limbo virtual da LimboAPI já isola cada conexão por construção (spawnPlayer é
        // por-conexão; a API não expõe player-list/visibilidade que vaze a entity ou o
        // tablist de outro jogador). Nada a fazer aqui pra esconder players.
        scheduleIdleKick(player);
        // isRegistered() é JDBC BLOQUEANTE, não pode rodar na thread de spawn do LimboAPI.
        // Vai pro pool; o prompt (showTitle/sendMessage são thread-safe) aparece quando volta.
        String name = this.player.getUsername();
        boolean queued = authService.trySubmit(() -> showPrompt(isRegistered(name)));
        if (!queued) {
            showPrompt(false); // pool cheio (raro): mostra prompt de registro; /login ainda funciona
        }
    }

    @Override
    public void onChat(String message) {
        LimboCommand cmd = LimboCommand.parse(message);
        switch (cmd.type()) {
            case LOGIN -> handleLogin(cmd.args());
            case REGISTER -> handleRegister(cmd.args());
            case RECOVER -> handleRecover(cmd.args());
            case OTHER -> send("login.usage"); // qualquer outra coisa = lembrete
        }
    }

    @Override
    public void onDisconnect() {
        cancelIdleKick();
    }

    // ---- handlers -----------------------------------------------------------

    private void handleLogin(List<String> args) {
        if (args.size() != 1) {
            send("login.usage");
            return;
        }
        String ip = ip();
        long locked = authService.lockoutRemainingSeconds(ip);
        if (locked > 0) { // IP em lockout: rejeita ANTES de enfileirar (read-only, sem gastar hash)
            send("login.too-many", "seconds", Long.toString(locked));
            return;
        }
        if (!authInFlight.compareAndSet(false, true)) { // 1 auth por conexão por vez (anti-spam)
            send("login.processing");
            return;
        }
        char[] pass = args.get(0).toCharArray();
        String name = player.getUsername();
        String uuid = player.getUniqueId().toString();
        boolean queued = authService.trySubmit(() -> {
            try {
                apply(authService.login(name, uuid, pass, ip));
            } finally {
                authInFlight.set(false);
            }
        });
        if (!queued) { // fila cheia: não deixa senha/flag pendente
            Arrays.fill(pass, '\0');
            authInFlight.set(false);
            send("error.busy");
        }
    }

    private void handleRegister(List<String> args) {
        if (args.size() != 2) {
            send("register.usage");
            return;
        }
        String ip = ip();
        long locked = authService.lockoutRemainingSeconds(ip);
        if (locked > 0) {
            send("login.too-many", "seconds", Long.toString(locked));
            return;
        }
        if (!authInFlight.compareAndSet(false, true)) {
            send("login.processing");
            return;
        }
        char[] pass = args.get(0).toCharArray();
        char[] confirm = args.get(1).toCharArray();
        String name = player.getUsername();
        String uuid = player.getUniqueId().toString();
        boolean queued = authService.trySubmit(() -> {
            try {
                apply(authService.register(name, uuid, pass, confirm, ip));
            } finally {
                authInFlight.set(false);
            }
        });
        if (!queued) {
            Arrays.fill(pass, '\0');
            Arrays.fill(confirm, '\0');
            authInFlight.set(false);
            send("error.busy");
        }
    }

    /**
     * /recover (pré-auth): sem args pede um código ao e-mail vinculado da conta; com
     * dois args ({@code <código> <nova senha>}) valida o código e troca a senha. A nova
     * senha é capturada aqui no limbo, não passa pelo dispatcher do Velocity nem vai ao
     * backend. O sucesso NÃO autentica: o jogador entra com /login depois.
     */
    private void handleRecover(List<String> args) {
        if (args.size() == 1) {
            send("recover.usage"); // código sem a nova senha: mostra o uso, não re-pede código
            return;
        }
        String name = player.getUsername();
        if (!emailFlow.tryAcquire(name)) {
            send("login.processing"); // já tem um /recuperar em voo
            return;
        }
        String ip = ip();
        Consumer<AuthOutcome> fb = outcome -> send(outcome.messageKey(), outcome.repl());
        if (args.size() >= 2) {
            char[] newPass = args.get(1).toCharArray();
            String code = args.get(0);
            boolean queued = authService.trySubmit(() -> {
                try {
                    emailFlow.recoverApply(name, code, newPass, fb);
                } finally {
                    emailFlow.release(name);
                }
            });
            if (!queued) {
                emailFlow.release(name);
                Arrays.fill(newPass, '\0');
                send("error.busy");
            }
        } else {
            boolean queued = authService.trySubmit(() -> {
                try {
                    emailFlow.recoverRequest(name, ip, fb);
                } finally {
                    emailFlow.release(name);
                }
            });
            if (!queued) {
                emailFlow.release(name);
                send("error.busy");
            }
        }
    }

    /** Aplica o resultado (roda na thread do executor; chamadas Velocity são thread-safe). */
    private void apply(AuthOutcome outcome) {
        // O hash Argon leva centenas de ms; o jogador pode ter desconectado nesse meio.
        // Se a conexão já morreu, NÃO marca autenticado, o DisconnectEvent já rodou
        // authState.clear, então marcar agora deixaria um UUID órfão imortal no AuthState
        // (leak sob rejoin agressivo), nem tenta mover uma sessão morta pro lobby.
        if (!player.isActive()) {
            return;
        }
        send(outcome.messageKey(), outcome.repl());
        if (!outcome.success()) {
            switch (outcome.messageKey()) {
                case "login.too-many" -> diag.signal("THROTTLE", player.getUsername() + " @ " + ip());
                case "register.ip-limit" -> diag.signal("REGISTER_DENY", player.getUsername() + " @ " + ip());
                case "login.wrong", "login.not-registered", "login.uuid-mismatch" ->
                        diag.signal("LOGIN_FAIL", player.getUsername() + " @ " + ip());
                default -> { }
            }
            return;
        }
        // Veto público ANTES de autenticar. Já estamos na thread do pool de auth, então o
        // disparo é BLOQUEANTE (firePreLoginBlocking) e o veto vale antes da marca. Negado:
        // não autentica e desconecta com o motivo (sem meio-estado preso no limbo). A janela
        // "saiu durante o veto" é coberta pelo CONC-1 logo abaixo (re-check de isActive()).
        ArcherPreLoginEvent pre = authEvents.firePreLoginBlocking(player, LoginType.PASSWORD);
        if (!pre.getResult().isAllowed()) {
            if (player.isActive()) {
                player.disconnect(AuthEvents.denyReason(pre));
            }
            return;
        }
        boolean wasRegistration = "register.success".equals(outcome.messageKey());
        // marca autenticado ANTES de cancelar o idle-kick, se o timer disparar na janela
        // da corrida, o callback vê isAuthenticated()=true e NÃO expulsa o jogador já logado.
        authState.markAuthenticated(player.getUniqueId());
        // CONC-1: re-checa isActive() DEPOIS de marcar, se o jogador caiu na janela mark/clear, desfaz
        // a marca (senão fica um UUID órfão imortal no AuthState sob rejoin agressivo).
        if (!player.isActive()) {
            authState.clear(player.getUniqueId());
            return;
        }
        cancelIdleKick();
        boolean moved;
        try {
            moved = limbo.sendToLobby(limboPlayer);
        } catch (RuntimeException e) {
            // sessão pode ter morrido entre o isActive() e aqui: não deixa "autenticado mas preso".
            authState.clear(player.getUniqueId());
            logger.warn("Falha ao mover {} ao lobby: {}", player.getUsername(), e.toString());
            return;
        }
        if (!moved) {
            // lobby fora -> não deixa preso no limbo; informa e desconecta. O cookie de sessão
            // faz auto-login na reconexão quando o lobby voltar.
            authState.clear(player.getUniqueId());
            logger.warn("Auth ok mas lobby '{}' indisponível para {}.", config.lobbyServer, player.getUsername());
            player.disconnect(LEGACY.deserialize(messages.raw("title.lobby-unavailable")));
        } else {
            logger.info("Autenticado e enviado ao lobby: {}", player.getUsername());
            // Notifica plugins de 3º (recompensa/sync/log). Registro também autentica -> // dispara RegisterEvent + LoginEvent. Fire-and-forget, fora do caminho crítico.
            if (wasRegistration) {
                authEvents.fireRegister(player);
            }
            authEvents.fireLogin(player, LoginType.PASSWORD);
        }
    }

    // ---- UI / util ----------------------------------------------------------

    private void showPrompt(boolean registered) {
        String titleKey = registered ? "title.login" : "title.register";
        String subKey = registered ? "title.login-sub" : "title.register-sub";
        if (config.uiTitle) {
            player.showTitle(Title.title(
                    LEGACY.deserialize(messages.raw(titleKey)),
                    LEGACY.deserialize(messages.raw(subKey)),
                    Title.Times.times(Duration.ofMillis(200), Duration.ofSeconds(8), Duration.ofMillis(200))));
        }
        if (config.uiActionBar) {
            player.sendActionBar(LEGACY.deserialize(messages.raw(subKey)));
        }
        if (config.uiSound) {
            player.playSound(net.kyori.adventure.sound.Sound.sound(
                    net.kyori.adventure.key.Key.key("minecraft:block.note_block.pling"),
                    net.kyori.adventure.sound.Sound.Source.MASTER, 1.0f, 1.0f));
        }
    }

    private void scheduleIdleKick(LimboPlayer limboPlayer) {
        int secs = config.limboTimeoutSeconds;
        if (secs <= 0) {
            return; // 0 = desligado
        }
        // disconnect(Component) é do Velocity Player; LimboPlayer.disconnect só aceita RegisteredServer.
        ScheduledFuture<?> f = limboPlayer.getScheduledExecutor().schedule(
                () -> {
                    // só expulsa se ainda NÃO autenticou (fecha a corrida cancel-vs-disparo).
                    if (!authState.isAuthenticated(player.getUniqueId())) {
                        player.disconnect(LEGACY.deserialize(messages.raw("login.timeout")));
                    }
                },
                secs, TimeUnit.SECONDS);
        ScheduledFuture<?> prev = idleKick.getAndSet(f); // CONC-2: troca atômica
        if (prev != null) {
            prev.cancel(false);
        }
    }

    private void cancelIdleKick() {
        ScheduledFuture<?> f = idleKick.getAndSet(null); // CONC-2
        if (f != null) {
            f.cancel(false);
        }
    }

    private boolean isRegistered(String name) {
        if (!authService.storageAvailable()) {
            return false; // banco fora: trata como não-registrado; login dará error.internal
        }
        try {
            return storage.isRegistered(name);
        } catch (Exception e) {
            return false;
        }
    }

    private void send(String key, String... repl) {
        player.sendMessage(prefixed(key, repl));
    }

    private Component prefixed(String key, String... repl) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key, repl));
    }

    private String ip() {
        if (player.getRemoteAddress() instanceof InetSocketAddress addr) {
            return addr.getAddress().getHostAddress();
        }
        return "unknown";
    }
}
