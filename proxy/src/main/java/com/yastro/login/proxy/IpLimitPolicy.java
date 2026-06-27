package com.yastro.login.proxy;

import java.util.Set;

/** Política de limite de contas por IP (anti contas-falsas/bots). */
public record IpLimitPolicy(boolean enabled, int max, Set<String> bypass) {
    public static IpLimitPolicy disabled() {
        return new IpLimitPolicy(false, 0, Set.of());
    }
}
