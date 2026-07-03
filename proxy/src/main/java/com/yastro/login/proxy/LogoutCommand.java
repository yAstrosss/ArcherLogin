package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import com.yastro.login.authcore.session.SessionService;
import com.yastro.login.common.AccountKey;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

public final class LogoutCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthState authState;
    private final Messages messages;
    private final AuthService authService;
    private final SessionService sessions;

    public LogoutCommand(AuthState authState, Messages messages, AuthService authService, SessionService sessions) {
        this.authState = authState;
        this.messages = messages;
        this.authService = authService;
        this.sessions = sessions;
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
        authState.clear(player.getUniqueId());
        String name = AccountKey.normalize(player.getUsername());
        authService.trySubmit(() -> sessions.revoke(name)); // delete fora da thread de comando
        player.disconnect(msg("logout.success"));
    }

    private Component msg(String key) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key));
    }
}
