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
import java.util.Arrays;

public class EncryptionAndCheck {

    private static final String ENCONDING="UTF-8";
    private static final String ALGORITHM_NAME="SM4";
    /**
     * 加密算法/分组加密模式/分组填充方式
     * PKCS5Padding - 以8个字节为一组进行分组加密
     * 定义分组加密模式使用: PKCS5Padding
     * */
    public static final String ALGORITHM_NAME_ECB_PADDING="SM4/ECB/PKCS7Padding";
    public static final int DEFAULT_KEY_SIZE=128;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成ECB暗号
     * ECB模式,(电子密码本模式: Electronic codebook)
     * algorithmName: 算法名字
     * mode: 模式
     * */
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

    public static byte[] encrypt_Ecb_Padding(byte[] key,byte[] data) throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING,Cipher.ENCRYPT_MODE,key);
        return cipher.doFinal(data);
    }

    // 解密
    public static String decryptEcb(String hexKey, String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException {

        String decryptStr = "";
        byte[] keyData = ByteUtils.fromHexString(hexKey);
        byte[] cipherData = ByteUtils.fromHexString(cipherText);
        byte[] bytes = decrypt_Ecb_Padding(keyData, cipherData);
        decryptStr = new String(bytes,ENCONDING);
        return decryptStr;
    }

    public static byte[] decrypt_Ecb_Padding(byte[] key,byte[] cipherText) throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING,Cipher.DECRYPT_MODE,key);
        return cipher.doFinal(cipherText);
    }

    public static boolean verifyEcb(String key,String cipherText,String param) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException {
        boolean verify = false;
        byte[] keyData = ByteUtils.fromHexString(key);
        byte[] cipherData = ByteUtils.fromHexString(cipherText);
        byte[] decryptData = decrypt_Ecb_Padding(keyData, cipherData);
        byte[] srcData = param.getBytes(ENCONDING);
        verify = Arrays.equals(decryptData, srcData);
        return verify;
    }


}
