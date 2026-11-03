// Test-only fixture producer; no Java/JAR is required by Go builds or tests.
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import org.bouncycastle.crypto.macs.DSTU7564Mac;
import org.bouncycastle.crypto.params.KeyParameter;

public final class GenerateKMACVectors {
    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder(value.length*2);
        for (byte b : value) out.append(String.format("%02x", b & 255));
        return out.toString();
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("output JSON required");
        byte[] jar = Files.readAllBytes(Paths.get(DSTU7564Mac.class.getProtectionDomain().getCodeSource().getLocation().toURI()));
        String sha = hex(MessageDigest.getInstance("SHA-256").digest(jar));
        if (!sha.equals("2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f")) {
            throw new IllegalStateException("unexpected reference artifact");
        }
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), "UTF-8"))) {
            out.print("{\"artifact\":\"org.bouncycastle:bcprov-jdk18on:1.86\",\"jarSHA256\":\""+sha+"\",\"vectors\":[\n");
            boolean first = true;
            for (int bits : new int[] {256,384,512}) {
                for (int keySize : new int[] {0,1,31,32,51,52,63,64,65,115,116,127,128,129,256}) {
                    for (int length : new int[] {0,1,51,52,64,111,112,128}) {
                        byte[] key = new byte[keySize], message = new byte[length];
                        for (int i=0;i<key.length;i++) key[i]=(byte)i;
                        for (int i=0;i<message.length;i++) message[i]=(byte)(29*i+7);
                        DSTU7564Mac mac = new DSTU7564Mac(bits);
                        mac.init(new KeyParameter(key));
                        mac.update(message,0,message.length);
                        byte[] result = new byte[mac.getMacSize()];
                        mac.doFinal(result,0);
                        if (!first) out.print(",\n");
                        first=false;
                        out.print("{\"algorithm\":\"kmac"+bits+"\",\"key\":\""+hex(key)+"\",\"message\":\""+hex(message)+"\",\"output\":\""+hex(result)+"\"}");
                    }
                }
            }
            out.print("\n]}\n");
            if (out.checkError()) throw new IOException("writing vectors failed");
        }
    }
}
