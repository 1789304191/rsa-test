package rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Maggie on 2017/9/15.
 */
public class RSAWORDBYSTRING {

    public static final String PUBLIC_KEY="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIfQ0uo706IOsNnsujXIme3dz8ws37KuAuchDWxIQkOUhg+UgdbFlrqZDgoYzHJ8Y1/ZXwGeX5PvAt1llVuhhiECAwEAAQ==";

    public static final String PRIVATE_KEY="MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAh9DS6jvTog6w2ey6NciZ7d3PzCzfsq4C5yENbEhCQ5SGD5SB1sWWupkOChjMcnxjX9lfAZ5fk+8C3WWVW6GGIQIDAQABAkB4m9phhkV3WaJ1tILcdksz8FGzWHpC+8K6LCD2cujdh3H65ggkrF4ZfjTODDEMne2sVUW821/Hy0+/5pCoGMcdAiEA/U3LZ2rJdbTdgm9yyRiiEvkVoCJnwkyB5cK/hhKjt38CIQCJQuVr/zzp/+lp5m8IhlLhlXPjCZgl+ylApikv2saSXwIgHVjrDRNRPgLzew5AhU4GUR5sw/3Yeal1j1It8HGuaC8CIAaeSyGh9PXzePW6PrBSibyG0EeqNsPeEGclm+bKzbhRAiAl31t0VyyfDmYNIQwF2MREXaG7WtK1z4a3xnUxUxUv8g==";

    public static final String CIPHER_ALGORITHM = "RSA";

    public static PublicKey getPublicKey(String key) throws Exception {

        byte[] keyBytes;

        keyBytes = Base64.decodeBase64(key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;
    }

    public static PrivateKey getPrivateKey(String key) throws Exception {

        byte[] keyBytes;

        keyBytes = Base64.decodeBase64(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }

    public static byte[] encrypt(byte[] data) throws Exception {
        PublicKey publicKey=getPublicKey(PUBLIC_KEY);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data) throws Exception {
        PrivateKey privateKey=getPrivateKey(PRIVATE_KEY);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }


    public static void main(String[] args) throws Exception {
        String s=new String(Base64.encodeBase64(encrypt("zaq1XSW@".getBytes())));
        System.out.println("====12345678经过公钥加密之后===="+s);
        System.out.println("====私钥解密===="+new String(decrypt(Base64.decodeBase64(s.getBytes()))));
    }
}
