package com.yastro.login.proxy;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import com.yastro.login.authcore.config.Messages;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

/**
 * {@code /recuperar} (pós-login). Por segurança, a recuperação que DEFINE uma nova senha
 * acontece só na tela de login (limbo), onde a senha é capturada como chat e NUNCA trafega como
 * argumento de comando (que vazaria no histórico do client e a outros plugins que escutem o
 * {@code CommandExecuteEvent}). Autenticado, este comando apenas orienta o jogador a usar
 * {@code /sair} e {@code /recuperar} no limbo. O fluxo pré-auth completo vive em {@link AuthLimboHandler}.
 */
public final class RecoverCommand implements SimpleCommand {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private final AuthState authState;
    private final Messages messages;

    public RecoverCommand(AuthState authState, Messages messages) {
        this.authState = authState;
        this.messages = messages;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            return;
        }
        if (!authState.isAuthenticated(player.getUniqueId())) {
            player.sendMessage(prefixed("guard.locked"));
            return;
        }
        player.sendMessage(prefixed("recover.use-login-screen"));
    }

    private Component prefixed(String key, String... repl) {
        return LEGACY.deserialize(messages.raw("prefix") + messages.raw(key, repl));
    }
}
