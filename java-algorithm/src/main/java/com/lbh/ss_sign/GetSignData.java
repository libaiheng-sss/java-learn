package com.lbh.ss_sign;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;

/**
 * 加签，验签
 * */
public class GetSignData {

    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    // 获取SM2椭圆曲线的参数
    private static final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
    private static Signature signature;
    static {
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            // 使用SM2参数初始化生成器
            kpg.initialize(sm2Spec);
            // 使用SM2的算法区域初始化密钥生成器
            kpg.initialize(sm2Spec, new SecureRandom());
            // 获取密钥对
            KeyPair keyPair = kpg.generateKeyPair();
            // 获取公私钥
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            System.out.println("私钥:"+privateKey);
            System.out.println("公钥:"+publicKey);
            // 生成SM2sign with sm3 签名验签算法实例
            signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException  e) {
            e.printStackTrace();
        }

    }

    // 加签
    public static String GetSignData(String param) throws InvalidKeyException, SignatureException {

        // 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
        // 签名原文
        byte[] plainText = param.getBytes(StandardCharsets.UTF_8);
        // 写入签名原文到算法中
        signature.update(plainText);
        // 计算签名值
        byte[] signatureValue = signature.sign();
        System.out.println("signatureValue:"+ Base64.toBase64String(signatureValue));
        return Base64.toBase64String(signatureValue);
    }

    // 验签
    public static boolean checkSignature(String param,String signString) throws InvalidKeyException, SignatureException {

        // 签名需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
        byte[] plainText = param.getBytes(StandardCharsets.UTF_8);
        // 写入待验签的签名原文到算法中
        signature.update(plainText);
        byte[] signValue = Base64.decode(signString);
        boolean verify = signature.verify(signValue);
        return verify;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException, InvalidKeyException, SignatureException, CertificateException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

//        加密字符串
        String str = "appId=43AF047BBA47FC8A1AE8EFB232BDBBCB&data={\"appId\":\"43AF047BBA47FC8A1AE8EFB232BDBBCB\",\"appUserId\":\"o8z4C5avQXqC0aWFPf1Mzu6D7WCQ_bd\",\"idNo\":\"350181199011193519\",\"idType\":\"01\",\"phoneNumber\":\"13763873033\",\"userName\":\"测试\"}&encType=SM4&signType=SM2&timestamp=20200207175759&transType=ec.gen.index&version=1.0.0&key=4117E877F5FA0A0188891283E4B617D5";
        String s = Base64.toBase64String(hash(str.getBytes(StandardCharsets.UTF_8)));
        System.out.println("SM3:"+s);
        BouncyCastleProvider provider = new BouncyCastleProvider();
// 获取SM2加密器
        Cipher cipher = Cipher.getInstance("SM2", provider);
// 初始化为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
// 加密并编码为base64格式
        s = java.util.Base64.getEncoder().encodeToString(cipher.doFinal(s.getBytes()));
        System.out.println("密文：" + s);
// 初始化为解密模式
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
// 解密
        s = new String(cipher.doFinal(java.util.Base64.getDecoder().decode(s)));
        System.out.println("解密：" + s);
    }

    public static byte[] hash(byte[] srcData){
        SM3Digest digest = new SM3Digest();
        digest.update(srcData,0,srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash,0);
        return hash;
    }
}
