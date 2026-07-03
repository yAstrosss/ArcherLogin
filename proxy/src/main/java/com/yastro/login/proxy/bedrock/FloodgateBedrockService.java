package com.yastro.login.proxy.bedrock;

import org.geysermc.floodgate.api.FloodgateApi;
import org.geysermc.floodgate.api.player.FloodgatePlayer;

import java.util.Optional;
import java.util.UUID;

/** Impl real sobre a FloodgateApi. Construída só quando o Floodgate está presente. */
public final class FloodgateBedrockService implements BedrockService {

    private final FloodgateApi api;

    public FloodgateBedrockService() {
        this.api = FloodgateApi.getInstance(); // lança se ausente -> factory cai no Noop
        if (this.api == null) {
            throw new IllegalStateException("FloodgateApi indisponível");
        }
    }

    @Override public boolean available() { return true; }

    @Override public boolean isBedrock(UUID playerId) {
        return api.isFloodgatePlayer(playerId);
    }

    @Override public Optional<String> username(UUID playerId) {
        FloodgatePlayer p = api.getPlayer(playerId);
        return p == null ? Optional.empty() : Optional.ofNullable(p.getCorrectUsername());
    }
}
