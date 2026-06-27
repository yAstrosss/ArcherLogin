package com.yastro.login.proxy;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Mascara os ARGUMENTOS de comandos sensíveis de auth digitados DEPOIS do login,
 * quando o jogador já está num backend. Sem isso, um "/login senha" digitado por
 * costume vaza em texto puro no console do backend ("issued server command").
 *
 * <p>O proxy intercepta via {@code CommandExecuteEvent} e troca os args por
 * símbolos aleatórios antes de encaminhar, a senha nunca chega ao backend.
 * Pré-auth o jogador está no limbo (não passa por aqui), então o login normal não
 * é afetado.
 *
 * <p>Lógica pura (sem tipos Velocity) para ser unit-testável.
 */
public final class SensitiveCommandFilter {

    /**
     * Comandos cujo argumento pode conter segredo (senha). Inclui SÓ os comandos do
     * limbo (login/register) que NÃO são comandos do proxy fora do limbo: já autenticado
     * num backend, "/login senha" não é comando do proxy -> seria encaminhado e vazaria o
     * texto cru no console do backend. Os demais ("email", "recuperar", "trocarsenha")
     * são comandos REAIS do proxy, executam aqui, não vão ao backend; mascará-los
     * cancelaria a execução.
     */
    private static final Set<String> SENSITIVE = Set.of(
            "login", "l", "register", "reg");

    private static final char[] SYMBOLS = "#@%&*!?$+=".toCharArray();

    private SensitiveCommandFilter() {
    }

    /**
     * @param command comando SEM a barra inicial (como vem do {@code CommandExecuteEvent}).
     * @return o comando com os argumentos mascarados, ou {@code null} se não for
     * sensível ou não tiver argumentos (nada a esconder).
     */
    public static String maskedOrNull(String command) {
        if (command == null) {
            return null;
        }
        String trimmed = command.strip();
        int sp = trimmed.indexOf(' ');
        if (sp < 0) {
            return null; // sem args: não há segredo a esconder (ex.: "/login" sozinho)
        }
        String word = trimmed.substring(0, sp).toLowerCase(Locale.ROOT);
        // Velocity aceita prefixo de namespace (ex.: "minecraft:login", "velocity:l"):
        // tira o prefixo antes de casar, senao "/minecraft:login senha" escaparia da
        // mascara e a senha vazaria crua no console do backend.
        int colon = word.lastIndexOf(':');
        if (colon >= 0) {
            word = word.substring(colon + 1);
        }
        if (!SENSITIVE.contains(word)) {
            return null;
        }
        return word + " " + randomSymbols();
    }

    private static String randomSymbols() {
        ThreadLocalRandom rnd = ThreadLocalRandom.current();
        int len = rnd.nextInt(5, 9); // 5..8 símbolos
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(SYMBOLS[rnd.nextInt(SYMBOLS.length)]);
        }
        return sb.toString();
    }
}
