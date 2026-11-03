// Generates public known-answer vectors using the unmodified Bouncy Castle JAR.
// See README.md for the pinned artifact and reproduction commands.
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.DSTU7624WrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public final class GenerateKWVectors {
    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder(value.length * 2);
        for (byte b : value) out.append(String.format("%02x", b & 255));
        return out.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("output JSON path required");
        byte[] jar = Files.readAllBytes(Paths.get(DSTU7624WrapEngine.class.getProtectionDomain()
            .getCodeSource().getLocation().toURI()));
        String jarHash = hex(MessageDigest.getInstance("SHA-256").digest(jar));
        if (!jarHash.equals("2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f")) {
            throw new IllegalStateException("unexpected Bouncy Castle artifact");
        }
        int[][] profiles = {{16, 16}, {16, 32}, {32, 32}, {32, 64}, {64, 64}};
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), "UTF-8"))) {
            out.println("{");
            out.println("  \"producer\": \"Bouncy Castle DSTU7624WrapEngine\",");
            out.println("  \"artifact\": \"org.bouncycastle:bcprov-jdk18on:1.86\",");
            out.println("  \"jarSHA256\": \"2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f\",");
            out.println("  \"vectors\": [");
            boolean first = true;
            for (int[] profile : profiles) {
                int blockSize = profile[0];
                byte[] key = new byte[profile[1]];
                for (int i = 0; i < key.length; i++) key[i] = (byte)i;
                for (int blocks : new int[] {20, 21, 22}) {
                    byte[] plain = new byte[blocks * blockSize];
                    for (int i = 0; i < plain.length - 2; i++) plain[i] = (byte)(29 * i + 7);
                    DSTU7624WrapEngine wrapper = new DSTU7624WrapEngine(blockSize * 8);
                    wrapper.init(true, new KeyParameter(key));
                    byte[] wrapped = wrapper.wrap(plain, 0, plain.length);
                    wrapper.init(false, new KeyParameter(key));
                    if (!Arrays.equals(plain, wrapper.unwrap(wrapped, 0, wrapped.length))) {
                        throw new IllegalStateException("reference unwrap failed");
                    }
                    if (!first) out.println(",");
                    first = false;
                    out.println("    {");
                    out.println("      \"name\": \"" + blockSize * 8 + "-" + key.length * 8 + "-" + blocks + "blocks\",");
                    out.println("      \"blockSize\": " + blockSize + ",");
                    out.println("      \"rounds\": " + 6 * (wrapped.length / (blockSize / 2) - 1) + ",");
                    out.println("      \"key\": \"" + hex(key) + "\",");
                    out.println("      \"plain\": \"" + hex(plain) + "\",");
                    out.println("      \"wrapped\": \"" + hex(wrapped) + "\"");
                    out.print("    }");
                }
            }
            out.println("\n  ]\n}");
            if (out.checkError()) throw new IllegalStateException("writing vectors failed");
        }
    }
}
