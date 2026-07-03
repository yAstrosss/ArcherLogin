package com.yastro.login.proxy.bedrock;

import com.velocitypowered.api.proxy.ProxyServer;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;

/** Seam sobre o Floodgate (dependência soft). Ausente/desligado -> Noop. */
public interface BedrockService {
    /** True se o Floodgate está presente e o suporte Bedrock ligado. */
    boolean available();
    /** True se o jogador é Bedrock (autoritativo via Floodgate no proxy). */
    boolean isBedrock(UUID playerId);
    /** Username Java que o Floodgate apresenta (com prefixo), se Bedrock. */
    Optional<String> username(UUID playerId);

    /** Escolhe a impl: Floodgate presente + configEnabled -> real; senão Noop. */
    static BedrockService detect(ProxyServer server, boolean configEnabled, Logger logger) {
        if (!configEnabled) {
            return new NoopBedrockService();
        }
        boolean present = server.getPluginManager().getPlugin("floodgate").isPresent();
        if (!present) {
            return new NoopBedrockService();
        }
        try {
            return new FloodgateBedrockService();
        } catch (Throwable t) {
            logger.warn("Floodgate detectado mas API indisponível; Bedrock desligado.", t);
            return new NoopBedrockService();
        }
    }
}
