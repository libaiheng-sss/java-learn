package com.lbh.ss_sign;

import org.bouncycastle.jcajce.provider.symmetric.SM4;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class EncryptionAndCheck {

    private static final String ENCONDING="UTF-8";
    private static final String ALGORITHM_NAME="SM4";
    public static final String ALGORITHM_NAME_ECB_PADDING="SM4/ECB/PKCS5Padding";
    public static final int DEFAULT_KEY_SIZE=128;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static Cipher generateEcbCipher(String algorithmName,int mode,byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithmName,BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
        cipher.init(mode,sm4Key);
        return cipher;
    }

    // 加密
    public static String encryptEcb(String keyString,String param) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException {

        String cipherText = "";
        byte[] keys = ByteUtils.fromHexString(keyString);
        byte[] bytes = param.getBytes(ENCONDING);
        byte[] cipherArray = encrypt_Ecb_Padding(keys, bytes);
        cipherText = ByteUtils.toHexString(cipherArray);
        return cipherText;
    }

    // 解密
    public static String decryptEcb(String hexKey, String cipherText){
        return null;
    }

    public static byte[] encrypt_Ecb_Padding(byte[] key,byte[] data) throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING,Cipher.ENCRYPT_MODE,key);
        return cipher.doFinal(data);
    }
}
