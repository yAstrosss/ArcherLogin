package com.yastro.login.proxy;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Parse puro do que chega em {@code onChat} no limbo. Sem tipos Velocity. */
public record LimboCommand(Type type, List<String> args) {

    public enum Type { LOGIN, REGISTER, RECOVER, OTHER }

    private static final LimboCommand OTHER = new LimboCommand(Type.OTHER, List.of());
    private static final Pattern WS = Pattern.compile("\\s+"); // pré-compilado (hot path de chat no limbo)

    public static LimboCommand parse(String chat) {
        if (chat == null) {
            return OTHER;
        }
        String trimmed = chat.strip();
        // Barra opcional: comando digitado por client real chega como command-packet
        // SEM "/" (LimboAPI repassa via onChat); pelo chat (ex.: bot) chega COM "/".
        if (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.isEmpty()) {
            return OTHER;
        }
        String[] parts = WS.split(trimmed);
        if (parts.length == 0 || parts[0].isEmpty()) {
            return OTHER;
        }
        String cmd = parts[0].toLowerCase(Locale.ROOT);
        Type resolvedType = switch (cmd) {
            case "login", "l" -> Type.LOGIN;
            case "register", "reg" -> Type.REGISTER;
            case "recuperar" -> Type.RECOVER;
            default -> Type.OTHER;
        };
        if (resolvedType == Type.OTHER) {
            return OTHER;
        }
        List<String> argList = List.of(parts).subList(1, parts.length);
        return new LimboCommand(resolvedType, List.copyOf(argList));
    }
}
