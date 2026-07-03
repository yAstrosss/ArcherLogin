package com.yastro.login.authcore.hash.legacy;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class BareHexVerifierTest {

    private final AuthMeMd5Verifier md5 = new AuthMeMd5Verifier();
    private final AuthMeSha512Verifier sha512 = new AuthMeSha512Verifier();

    // md5("password") = 5f4dcc3b5aa765d61d8327deb882cf99
    private static final String MD5_PW = "5f4dcc3b5aa765d61d8327deb882cf99";
    // sha512("password") = b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86
    private static final String SHA512_PW =
        "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86";

    @Test
    void md5MatchesOnly32Hex() {
        assertTrue(md5.matches(MD5_PW));
        assertFalse(md5.matches(SHA512_PW));      // 128 hex
        assertFalse(md5.matches("$SHA$a$b"));
        assertFalse(md5.matches("5f4dcc3b5aa765d61d8327deb882cf9"));  // 31 chars
    }

    @Test
    void md5Verifies() {
        assertTrue(md5.verify("password".toCharArray(), MD5_PW));
        assertFalse(md5.verify("wrong".toCharArray(), MD5_PW));
    }

    @Test
    void sha512MatchesOnly128Hex() {
        assertTrue(sha512.matches(SHA512_PW));
        assertFalse(sha512.matches(MD5_PW));
    }

    @Test
    void sha512Verifies() {
        assertTrue(sha512.verify("password".toCharArray(), SHA512_PW));
        assertFalse(sha512.verify("wrong".toCharArray(), SHA512_PW));
    }

    @Test
    void md5NullStoredFailsClosedNeverThrows() {
        assertFalse(md5.verify("password".toCharArray(), null));
    }

    @Test
    void sha512NullStoredFailsClosedNeverThrows() {
        assertFalse(sha512.verify("password".toCharArray(), null));
    }
}
