package com.lbh.ss_sign;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.*;
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
            // 生成SM2sign with sm3 签名验签算法实例
            signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
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
}
