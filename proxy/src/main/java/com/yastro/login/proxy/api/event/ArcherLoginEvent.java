package com.yastro.login.proxy.api.event;

import com.velocitypowered.api.proxy.Player;

/**
 * Disparado pelo ArcherLogin DEPOIS que um jogador foi autenticado com sucesso e movido
 * ao lobby. Notificação (não cancelável), para plugins reagirem (recompensa de boas-
 * vindas, sync de stats, log, integração Discord, etc.). É o análogo do {@code LoginEvent}
 * do AuthMe.
 *
 * <p>Para um registro, este evento é disparado JUNTO com {@link ArcherRegisterEvent}
 * (registrar aqui também autentica).
 */
public final class ArcherLoginEvent {

    private final Player player;
    private final LoginType type;

    public ArcherLoginEvent(Player player, LoginType type) {
        this.player = player;
        this.type = type;
    }

    /** O jogador autenticado. */
    public Player getPlayer() {
        return player;
    }

    /** Como o jogador autenticou (senha ou auto-login premium). */
    public LoginType getType() {
        return type;
    }
}
