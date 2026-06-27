package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

public final class LogoutCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthState authState;
    private final Messages messages;

    public LogoutCommand(AuthState authState, Messages messages) {
        this.authState = authState;
        this.messages = messages;
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
        player.disconnect(msg("logout.success"));
    }

    private Component msg(String key) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key));
    }
}
