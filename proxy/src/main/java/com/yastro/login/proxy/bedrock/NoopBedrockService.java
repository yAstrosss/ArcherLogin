package com.yastro.login.proxy.bedrock;

import java.util.Optional;
import java.util.UUID;

/** Sem Floodgate: tudo desligado. Servidor só-Java usa este. */
public final class NoopBedrockService implements BedrockService {
    @Override public boolean available() { return false; }
    @Override public boolean isBedrock(UUID playerId) { return false; }
    @Override public Optional<String> username(UUID playerId) { return Optional.empty(); }
}
