package rsa;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Maggie on 2017/9/18.
 * rsa通过私钥签名与公钥验签
 */
public class RSASIGNTEST {

    public static final String PUBLIC_KEY="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIVrWueKfUrNI8kid3AaA8o1vOCqjyd7IbVKRGixBoiKZT9LwQQQEA3Obe2xgzI7F0YSN/hrICHECO4EeVSfXxkCAwEAAQ==";

    public static final String PRIVATE_KEY="MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAh9DS6jvTog6w2ey6NciZ7d3PzCzfsq4C5yENbEhCQ5SGD5SB1sWWupkOChjMcnxjX9lfAZ5fk+8C3WWVW6GGIQIDAQABAkB4m9phhkV3WaJ1tILcdksz8FGzWHpC+8K6LCD2cujdh3H65ggkrF4ZfjTODDEMne2sVUW821/Hy0+/5pCoGMcdAiEA/U3LZ2rJdbTdgm9yyRiiEvkVoCJnwkyB5cK/hhKjt38CIQCJQuVr/zzp/+lp5m8IhlLhlXPjCZgl+ylApikv2saSXwIgHVjrDRNRPgLzew5AhU4GUR5sw/3Yeal1j1It8HGuaC8CIAaeSyGh9PXzePW6PrBSibyG0EeqNsPeEGclm+bKzbhRAiAl31t0VyyfDmYNIQwF2MREXaG7WtK1z4a3xnUxUxUv8g==";

    public static final String  SIGN_ALGORITHMS = "SHA1WithRSA";

    public static String sign(String content, String privateKey, String input_charset)
    {
        try
        {
            PKCS8EncodedKeySpec priPKCS8 	= new PKCS8EncodedKeySpec( Base64.decode(privateKey) );
            KeyFactory keyf 				= KeyFactory.getInstance("RSA");
            PrivateKey priKey 				= keyf.generatePrivate(priPKCS8);

            java.security.Signature signature = java.security.Signature
                    .getInstance(SIGN_ALGORITHMS);

            signature.initSign(priKey);
            signature.update( content.getBytes(input_charset) );

            byte[] signed = signature.sign();

            return Base64.encode(signed);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return null;
    }


    public static boolean verify(String content, String sign, String ali_public_key, String input_charset)
    {
        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = Base64.decode(ali_public_key);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));


            java.security.Signature signature = java.security.Signature
                    .getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update( content.getBytes(input_charset) );

            boolean bverify = signature.verify( Base64.decode(sign) );
            return bverify;

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return false;
    }

    public static void main(String[] args) {
        String sign=sign("zaq1XSW@",PRIVATE_KEY,"UTF-8");
        System.out.println("sign:"+sign);
        System.out.println(verify("zaq1XSW@",sign,PUBLIC_KEY,"UTF-8"));
    }




}
