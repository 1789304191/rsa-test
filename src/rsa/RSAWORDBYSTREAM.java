package rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by Maggie on 2017/9/15.
 */
public class RSAWORDBYSTREAM {

    public static final String CIPHER_ALGORITHM = "RSA";

    public static byte[] encrypt(byte[] data) throws Exception {
        ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("F:\\Resp\\rsa-test\\public.key"));
        Key key = (Key) keyIn.readObject();
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data) throws Exception {
        ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("F:\\Resp\\rsa-test\\private.key"));
        Key key = (Key) keyIn.readObject();
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        String s="1QAZXSW@";
        String after=new String(Base64.encodeBase64(encrypt(s.getBytes())));
        System.out.println(after);
        String before=new String(decrypt(Base64.decodeBase64(after)));
        System.out.println(before);
    }
}
