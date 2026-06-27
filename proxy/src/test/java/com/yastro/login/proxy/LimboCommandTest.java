package com.yastro.login.proxy;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LimboCommandTest {

    @Test
    void parsesLoginWithArg() {
        LimboCommand c = LimboCommand.parse("/login segredo");
        assertEquals(LimboCommand.Type.LOGIN, c.type());
        assertEquals(List.of("segredo"), c.args());
    }

    @Test
    void parsesRegisterWithTwoArgs() {
        LimboCommand c = LimboCommand.parse("/register abc abc");
        assertEquals(LimboCommand.Type.REGISTER, c.type());
        assertEquals(List.of("abc", "abc"), c.args());
    }

    @Test
    void commandIsCaseInsensitive() {
        assertEquals(LimboCommand.Type.LOGIN, LimboCommand.parse("/LOGIN x").type());
    }

    @Test
    void loginWithoutArgsHasEmptyArgList() {
        LimboCommand c = LimboCommand.parse("/login");
        assertEquals(LimboCommand.Type.LOGIN, c.type());
        assertEquals(List.of(), c.args());
    }

    @Test
    void plainChatIsOther() {
        assertEquals(LimboCommand.Type.OTHER, LimboCommand.parse("oi pessoal").type());
        assertEquals(LimboCommand.Type.OTHER, LimboCommand.parse("/help").type());
        assertEquals(LimboCommand.Type.OTHER, LimboCommand.parse(null).type());
    }

    @Test
    void collapsesExtraSpaces() {
        assertEquals(List.of("a", "b"), LimboCommand.parse("/register a b").args());
    }

    @Test
    void parsesShortAliases() {
        assertEquals(LimboCommand.Type.LOGIN, LimboCommand.parse("/l pass").type());
        assertEquals(LimboCommand.Type.REGISTER, LimboCommand.parse("/reg p p").type());
    }
}
