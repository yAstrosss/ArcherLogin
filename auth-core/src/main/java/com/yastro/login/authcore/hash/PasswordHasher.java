package com.yastro.login.authcore.hash;

import at.favre.lib.crypto.bcrypt.BCrypt;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;

/**
 * Hash de senha do ArcherLogin.
 *
 * <p><b>Padrão: Argon2id</b> (puro Java, via BouncyCastle), parâmetros
 * configuráveis. Os defaults ({@code m=19456 KiB, t=2, p=1}) seguem o baseline do
 * OWASP e são calibrados para o PICO sincronizado de logins (ex.: restart com
 * dezenas de jogadores reconectando ao mesmo tempo), não para o caso médio, daí
 * a memória conservadora. Subir {@code m} sem limitar logins concorrentes pode
 * estourar a RAM no pico.
 *
 * <p><b>IMPORTANTE:</b> {@link #hash} e {@link #verify} são CAROS (dezenas a
 * centenas de ms) e NUNCA devem rodar na main thread do servidor, sempre num
 * pool limitado (ver AuthHandler).
 *
 * <p>Para compatibilidade de importação (AuthMe/nLogin), {@link #verify} também
 * reconhece hashes <b>bcrypt</b> ({@code $2a$/$2b$/$2y$}). {@link #needsRehash}
 * sinaliza quando um hash legado deve ser re-gerado em Argon2id no próximo login.
 *
 * <p>Formato de saída (PHC): {@code $argon2id$v=19$m=<kib>,t=<it>,p=<par>$<saltB64>$<hashB64>}
 * (Base64 sem padding, como manda a especificação Argon2).
 */
public final class PasswordHasher {

    private static final int SALT_LEN = 16;
    private static final int HASH_LEN = 32;
    private static final int ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13; // 0x13 = 19

    private static final Base64.Encoder B64_ENC = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64_DEC = Base64.getDecoder();

    // Entrada fixa para o hash dummy de anti-enumeração (timing). Conteúdo irrelevante.
    private static final byte[] DUMMY_PW = "yAstroLoginDummyPassword".getBytes(StandardCharsets.UTF_8);
    private static final byte[] DUMMY_SALT = new byte[SALT_LEN];

    private final SecureRandom random = new SecureRandom();

    private final int memoryKib;
    private final int iterations;
    private final int parallelism;

    public PasswordHasher(int memoryKib, int iterations, int parallelism) {
        this.memoryKib = memoryKib;
        this.iterations = iterations;
        this.parallelism = parallelism;
    }

    /** Gera o hash Argon2id no formato PHC. */
    public String hash(char[] password) {
        byte[] salt = new byte[SALT_LEN];
        random.nextBytes(salt);
        byte[] pw = toUtf8(password);
        try {
            byte[] out = rawHash(pw, salt, memoryKib, iterations, parallelism);
            try {
                return encode(salt, out, memoryKib, iterations, parallelism);
            } finally {
                Arrays.fill(out, (byte) 0);
            }
        } finally {
            Arrays.fill(pw, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
    }

    /**
     * Verifica a senha contra um hash armazenado. Suporta Argon2id (nativo) e
     * bcrypt (legado/importado). Comparação em tempo constante.
     */
    public boolean verify(char[] password, String stored) {
        if (stored == null || stored.isEmpty()) {
            return false;
        }
        if (isBcrypt(stored)) {
            return verifyBcrypt(password, stored);
        }
        if (stored.startsWith("$argon2id$")) {
            return verifyArgon2(password, stored);
        }
        return false; // formato desconhecido: nunca autentica
    }

    /**
     * Roda um Argon2id descartável com os parâmetros atuais e descarta o resultado.
     * Serve para IGUALAR o tempo de resposta quando a conta não existe, sem isto,
     * o caminho "não registrado" responde instantâneo e vira oráculo de enumeração.
     */
    public void hashDummy() {
        byte[] out = rawHash(DUMMY_PW, DUMMY_SALT, memoryKib, iterations, parallelism);
        Arrays.fill(out, (byte) 0);
    }

    /** True se o hash não é Argon2id com os parâmetros atuais (deve ser re-gerado). */
    public boolean needsRehash(String stored) {
        if (stored == null || !stored.startsWith("$argon2id$")) {
            return true; // bcrypt/legado -> migrar
        }
        try {
            Parsed p = parse(stored);
            return p.memoryKib != memoryKib || p.iterations != iterations
                    || p.parallelism != parallelism;
        } catch (RuntimeException e) {
            return true;
        }
    }

    // ---- Argon2id -----------------------------------------------------------

    private boolean verifyArgon2(char[] password, String stored) {
        byte[] pw = toUtf8(password);
        try {
            Parsed p = parse(stored);
            byte[] expected = p.hash;
            byte[] actual = rawHash(pw, p.salt, p.memoryKib, p.iterations, p.parallelism);
            try {
                return MessageDigest.isEqual(expected, actual);
            } finally {
                Arrays.fill(actual, (byte) 0);
            }
        } catch (RuntimeException e) {
            return false;
        } finally {
            Arrays.fill(pw, (byte) 0);
        }
    }

    private static byte[] rawHash(byte[] password, byte[] salt,
                                  int memoryKib, int iterations, int parallelism) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(ARGON2_VERSION)
                .withMemoryAsKB(memoryKib)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[HASH_LEN];
        gen.generateBytes(password, out);
        return out;
    }

    private static String encode(byte[] salt, byte[] hash,
                                 int memoryKib, int iterations, int parallelism) {
        return "$argon2id$v=" + ARGON2_VERSION
                + "$m=" + memoryKib + ",t=" + iterations + ",p=" + parallelism
                + "$" + B64_ENC.encodeToString(salt)
                + "$" + B64_ENC.encodeToString(hash);
    }

    private record Parsed(int memoryKib, int iterations, int parallelism,
                          byte[] salt, byte[] hash) {
    }

    private static Parsed parse(String phc) {
        // $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
        String[] parts = phc.split("\\$");
        // parts[0]="", [1]="argon2id", [2]="v=19", [3]="m=..,t=..,p=..", [4]=salt, [5]=hash
        if (parts.length != 6 || !"argon2id".equals(parts[1])) {
            throw new IllegalArgumentException("PHC Argon2id inválido");
        }
        int m = 0, t = 0, p = 0;
        for (String kv : parts[3].split(",")) {
            String[] e = kv.split("=", 2);
            switch (e[0]) {
                case "m" -> m = Integer.parseInt(e[1]);
                case "t" -> t = Integer.parseInt(e[1]);
                case "p" -> p = Integer.parseInt(e[1]);
                default -> { /* ignora chaves desconhecidas */ }
            }
        }
        byte[] salt = B64_DEC.decode(parts[4]);
        byte[] hash = B64_DEC.decode(parts[5]);
        return new Parsed(m, t, p, salt, hash);
    }

    // ---- bcrypt (somente verificação de hashes importados) ------------------

    private static boolean isBcrypt(String stored) {
        return stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$");
    }

    private static boolean verifyBcrypt(char[] password, String stored) {
        // bcrypt rejeita senha > 72 bytes lancando excecao (at.favre.lib, estrategia strict).
        // Embora o tamanho seja validado antes no fluxo de login, tratamos QUALQUER falha como
        // "senha incorreta" (fail-closed): evita excecao nao-tratada no pool de auth e fecha um
        // oraculo de tipo-de-hash (senha > 72 nunca pode ter sido registrada).
        try {
            BCrypt.Result r = BCrypt.verifyer().verify(password, stored.toCharArray());
            return r.verified;
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- util ---------------------------------------------------------------

    private static byte[] toUtf8(char[] password) {
        CharBuffer cb = CharBuffer.wrap(password);
        ByteBuffer bb = StandardCharsets.UTF_8.encode(cb);
        byte[] out = new byte[bb.remaining()];
        bb.get(out);
        // limpa o buffer intermediário
        if (bb.hasArray()) {
            Arrays.fill(bb.array(), (byte) 0);
        }
        return out;
    }

    /** Normaliza para comparação de prefixo de algoritmo (debug/admin). */
    public static String algorithmOf(String stored) {
        if (stored == null) {
            return "none";
        }
        String s = stored.toLowerCase(Locale.ROOT);
        if (s.startsWith("$argon2id$")) {
            return "argon2id";
        }
        if (s.startsWith("$2")) {
            return "bcrypt";
        }
        return "desconhecido";
    }
}
