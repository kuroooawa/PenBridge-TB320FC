import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyExport {
    public static void main(String[] args) throws Exception {
        String ksPath = args[0];
        String pass = args[1];
        String alias = args[2];
        String certOut = args[3];
        String spkiOut = args[4];
        String paramsOut = args[5];

        KeyStore ks = KeyStore.getInstance(new java.io.File(ksPath), pass.toCharArray());
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pass.toCharArray());
        Certificate cert = ks.getCertificate(alias);

        try (FileOutputStream out = new FileOutputStream(certOut)) {
            out.write(cert.getEncoded());
        }
        try (FileOutputStream out = new FileOutputStream(spkiOut)) {
            out.write(cert.getPublicKey().getEncoded());
        }
        RSAPrivateKey rk = (RSAPrivateKey) pk;
        RSAPublicKey pub = (RSAPublicKey) cert.getPublicKey();
        try (PrintWriter w = new PrintWriter(paramsOut, "UTF-8")) {
            w.println("modulus=" + rk.getModulus().toString(16));
            w.println("privateExponent=" + rk.getPrivateExponent().toString(16));
            w.println("publicExponent=" + pub.getPublicExponent().toString(16));
            w.println("bits=" + rk.getModulus().bitLength());
        }
        System.out.println("cert bytes=" + cert.getEncoded().length
                + " spki bytes=" + cert.getPublicKey().getEncoded().length
                + " modulus bits=" + rk.getModulus().bitLength());
    }
}
