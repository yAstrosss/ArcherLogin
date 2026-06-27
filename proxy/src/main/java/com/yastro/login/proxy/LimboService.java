package com.yastro.login.proxy;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.elytrium.limboapi.api.Limbo;
import net.elytrium.limboapi.api.LimboFactory;
import net.elytrium.limboapi.api.LimboSessionHandler;
import net.elytrium.limboapi.api.chunk.VirtualWorld;
import net.elytrium.limboapi.api.chunk.Dimension;
import net.elytrium.limboapi.api.command.LimboCommandMeta;
import net.elytrium.limboapi.api.player.LimboPlayer;
import org.slf4j.Logger;

import java.util.List;
import java.util.Optional;

/**
 * Encapsula o LimboAPI: cria o limbo virtual uma vez no boot e oferece entrada/saída.
 * O jogador não-autenticado vive aqui; chat não chega a backend nenhum.
 */
public final class LimboService {

    private final ProxyServer server;
    private final YAstroLoginProxy plugin;
    private final Logger logger;
    private final LimboFactory factory;
    private final ProxyConfig config;

    private Limbo limbo;

    public LimboService(ProxyServer server, YAstroLoginProxy plugin, Logger logger,
                        LimboFactory factory, ProxyConfig config) {
        this.server = server;
        this.plugin = plugin;
        this.logger = logger;
        this.factory = factory;
        this.config = config;
    }

    public void init() {
        Dimension dim;
        try {
            dim = Dimension.valueOf(config.limboDimension);
        } catch (IllegalArgumentException e) {
            dim = Dimension.THE_END;
            logger.warn("limbo-dimension inválida ({}); usando THE_END.", config.limboDimension);
        }
        VirtualWorld world = factory.createVirtualWorld(dim, 0.0, 64.0, 0.0, 0.0f, 0.0f);
        this.limbo = factory.createLimbo(world).setName("ArcherLogin");
        // Declara os comandos de auth no limbo para o client os reconhecer (texto branco
        // + tab-complete, em vez de "comando desconhecido" em vermelho). O input continua
        // sendo tratado em AuthLimboHandler.onChat, aqui é só a árvore de comandos do client.
        this.limbo.registerCommand(new LimboCommandMeta(List.of("login", "l", "register", "reg", "recuperar")));

        // blindness: a LimboAPI 1.1.27 não expõe efeito de poção/mob-effect limpo (LimboPlayer só
        // tem writePacket cru, descartado por decisão). Avisa uma vez e ignora o toggle.
        if (config.limboBlindness) {
            logger.warn("limbo-blindness=true mas a versão atual do LimboAPI não expõe efeito de poção limpo; "
                    + "ignorando (feature não-suportada nesta plataforma).");
        }
    }

    public boolean isReady() {
        return limbo != null;
    }

    /** Libera o limbo virtual. Chamar no shutdown do proxy. */
    public void shutdown() {
        if (limbo != null) {
            limbo.dispose();
        }
    }

    /** Coloca o jogador no limbo com o handler dado (auth ou troca-de-senha). */
    public void enterLimbo(Player player, LimboSessionHandler handler) {
        limbo.spawnPlayer(player, handler);
    }

    /** Tira o jogador do limbo mandando pro lobby; false se o lobby não existe. */
    public boolean sendToLobby(LimboPlayer limboPlayer) {
        Optional<RegisteredServer> lobby = server.getServer(config.lobbyServer);
        if (lobby.isEmpty()) {
            return false;
        }
        limboPlayer.disconnect(lobby.get());
        return true;
    }
}
