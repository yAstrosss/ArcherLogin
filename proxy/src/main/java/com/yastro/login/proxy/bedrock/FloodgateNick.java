package com.yastro.login.proxy.bedrock;

/** Heurística pura sobre o username de PreLogin (sem uniqueId disponível ainda). */
public final class FloodgateNick {

    private FloodgateNick() {
    }

    /** Prefixo Floodgate padrão é um char não-alfanumérico (ex.: '.') na frente do nick.
     * Heurística de PreLogin (só o username disponível); a checagem autoritativa
     * (isBedrock por UUID) é feita no PostLogin. */
    public static boolean looksLikeFloodgate(String username) {
        if (username.isEmpty()) {
            return false;
        }
        char c = username.charAt(0);
        boolean normal = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9') || c == '_';
        return !normal; // prefixo Floodgate (ex.: '.')
    }
}
