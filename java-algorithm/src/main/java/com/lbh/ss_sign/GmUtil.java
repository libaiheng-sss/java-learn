package com.lbh.ss_sign;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;

import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class GmUtil {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    private static Signature signature;
    public static void getKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // 获取SM2椭圆曲线的参数
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);
        // 使用SM2的算法区域初始化密钥生成器
        kpg.initialize(sm2Spec, new SecureRandom());
        // 获取密钥对
        KeyPair keyPair = kpg.generateKeyPair();
         publicKey = keyPair.getPublic();
         privateKey = keyPair.getPrivate();
    }

    public static String sign(String param) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        signature = Signature.getInstance(GMObjectIdentifiers.sm2sign_with_sm3.toString(), new BouncyCastleProvider());
        signature.initSign(privateKey);
        // 签名原文
        byte[] plainText = param.getBytes(StandardCharsets.UTF_8);
// 写入签名原文到算法中
        signature.update(plainText);
// 计算签名值
        byte[] signatureValue = signature.sign();
        System.out.println("signature: \n" + Hex.toHexString(signatureValue));
        return Hex.toHexString(signatureValue);
    }

    public static boolean verify(String param,String signStr) throws InvalidKeyException, SignatureException {
// 签名需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
// 写入待验签的签名原文到算法中
        signature.update(param.getBytes(StandardCharsets.UTF_8));
// 验签
        System.out.println("Signature verify result: " + signature.verify(signStr.getBytes(StandardCharsets.UTF_8)));
        return signature.verify(signStr.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        final BouncyCastleProvider bc = new BouncyCastleProvider();

        /*
        >> 公钥BASE64: MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==
        >> 私钥BASE64: MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx
        signature:
        3045022100ff9a872f21e47d4fba8f37b48a62cc2e6fdde843a40cbc96242536afc10a395e02203bbab982d1bb6a7ee5f5f6b34cd887c255ae4dcc14dd87ecae2e0392611b7a8c
         */
//        // 公私钥是16进制情况下解码
//        byte[] encPub = Hex.decode("...");
//        byte[] encPriv =  Hex.decode("...");
        byte[] encPub = Base64.decode("MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAESic24soUECzuSh2aYH0e+hQYh+/I01NmfjOnm5mwyUEYQvNCPTzn3BlNyufgMV+DWLUKV+2h0+PVel9jYTfG8Q==");
        byte[] encPriv = Base64.decode("MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQg0dYU+I6IdiSe8bvWlsHuWfsjSn3XFZqOGWO3K1814O6gCgYIKoEcz1UBgi2hRANCAARKJzbiyhQQLO5KHZpgfR76FBiH78jTU2Z+M6ebmbDJQRhC80I9POfcGU3K5+AxX4NYtQpX7aHT49V6X2NhN8bx");
        String str = "appId=43AF047BBA47FC8A1AE8EFB232BDBBCB&data={\"appId\":\"43AF047BBA47FC8A1AE8EFB232BDBBCB\",\"appUserId\":\"o8z4C5avQXqC0aWFPf1Mzu6D7WCQ_bd\",\"idNo\":\"350181199011193519\",\"idType\":\"01\",\"phoneNumber\":\"13763873033\",\"userName\":\"测试\"}&encType=SM4&signType=SM2&timestamp=20200207175759&transType=ec.gen.index&version=1.0.0&key=4117E877F5FA0A0188891283E4B617D5";
        byte[] plainText = str.getBytes(StandardCharsets.UTF_8);

        KeyFactory keyFact = KeyFactory.getInstance("EC", bc);
        // 根据采用的编码结构反序列化公私钥
        PublicKey pub = keyFact.generatePublic(new X509EncodedKeySpec(encPub));
        PrivateKey priv = keyFact.generatePrivate(new PKCS8EncodedKeySpec(encPriv));

        Signature signature2 = Signature.getInstance("SM3withSm2", bc);
        signature2.initSign(priv);
        signature2.update(plainText);
        byte[] sin = signature2.sign();
        System.out.println(Base64.toBase64String(sin));
        Signature signature = Signature.getInstance("SM3withSm2", bc);
        signature.initVerify(pub);
        signature.update(plainText);
        // 验证签名值
        boolean res = signature.verify(signature2.sign());
        System.out.println(">> 验证结果:" + res);
    }

}
