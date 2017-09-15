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
public class RSAWORDTEST {

    public static final String PUBLIC_KEY="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIZGRwOr9FJ9fwzoLUQAETKXvc6tTKTckIZQAqsgicSSHwNgKaI1R8XIToB6j2qLxNONRwGYAYMGfqn0e7/WZf0CAwEAAQ==";

    public static final String PRIVATE_KEY="MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAhkZHA6v0Un1/DOgtRAARMpe9zq1MpNyQhlACqyCJxJIfA2ApojVHxchOgHqPaovE041HAZgBgwZ+qfR7v9Zl/QIDAQABAkAiBeCsn3+S/1WYEaSWnGW/Kg/gNK09AN5mChQDBIWkFvwYd+ljRn1vn3/zIOdjMFqJNQ0F2CfGhAdGLuKw3JMBAiEAyXj3wHglZlk9JyMstfNsaUMy63eRp0SCTetCuApcAB0CIQCqnX4uOcHs+/3TTl4+iC08hcir93YIX9F1jyYM2MrXYQIhAJzk0yrTZWyaugCsZ7kZ46bladXsu0SjGUZMmxxvFM4RAiEAjFVIYRsusA9A4toV2JdHpf1gZln/orm1Xl2k7XIvvWECIHhn4K70EhpknH02KLTWQ5Z4PzVzj0iFtN+OsMBFGaIM";

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
        String s=new String(Base64.encodeBase64(encrypt("12345678".getBytes())));
        System.out.println("====12345678经过公钥加密之后===="+s);
        System.out.println("====私钥解密===="+new String(decrypt(Base64.decodeBase64(s.getBytes()))));
    }
}
