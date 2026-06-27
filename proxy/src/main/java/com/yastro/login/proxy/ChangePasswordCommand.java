package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.slf4j.Logger;

/**
 * {@code /changepassword} (sem argumentos): manda o jogador autenticado pro limbo,
 * onde a senha atual e a nova são digitadas como chat seguro (capturado pelo LimboAPI).
 * Assim a senha NUNCA passa pelos argumentos do dispatcher do Velocity (que seriam
 * vistos por command-loggers) nem viram chat público se o jogador esquecer a barra (H3).
 */
public final class ChangePasswordCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthService authService;
    private final LimboService limbo;
    private final AuthState authState;
    private final Messages messages;
    private final ProxyConfig config;
    private final Logger logger;

    public ChangePasswordCommand(AuthService authService, LimboService limbo, AuthState authState,
                                 Messages messages, ProxyConfig config, Logger logger) {
        this.authService = authService;
        this.limbo = limbo;
        this.authState = authState;
        this.messages = messages;
        this.config = config;
        this.logger = logger;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            return;
        }
        if (!authState.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(msg("logout.not-auth"));
            return;
        }
        if (limbo == null || !limbo.isReady()) {
            player.sendMessage(msg("changepass.unavailable"));
            return;
        }
        // Sem args de propósito (H3): a senha é pedida no limbo, em chat seguro.
        limbo.enterLimbo(player, new ChangePasswordLimboHandler(authService, limbo, messages, config, logger));
    }

    private Component msg(String key) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key));
    }
}
