package com.yastro.login.common;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AccountKeyTest {

    @Test
    void normalize_lowercases() {
        assertEquals("pedro3030", AccountKey.normalize("Pedro3030"));
        assertEquals("pedro3030", AccountKey.normalize("PEDRO3030"));
        assertEquals("pedro3030", AccountKey.normalize("pedro3030"));
    }

    @Test
    void normalize_isStableAcrossCasing() {
        // O ponto do choke-point: variações de case colapsam na MESMA chave.
        assertEquals(AccountKey.normalize("AbC_xyz"), AccountKey.normalize("aBc_XYZ"));
    }

    @Test
    void normalize_usesRootLocale_notDefault() {
        // Independe do locale default da JVM (sem bug do "i-turco"): "I" -> "i", nunca "ı".
        assertEquals("login_i", AccountKey.normalize("LOGIN_I"));
        assertEquals('i', AccountKey.normalize("I").charAt(0));
        // Confirma que não é o toLowerCase do locale default por acaso.
        assertEquals("I".toLowerCase(Locale.ROOT), AccountKey.normalize("I"));
    }

    @Test
    void normalize_nullThrows_sameAsRawToLowerCase() {
        // Comportamento preservado: NPE em null, igual ao name.toLowerCase(...) cru.
        assertThrows(NullPointerException.class, () -> AccountKey.normalize(null));
    }
}
