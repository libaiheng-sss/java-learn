package com.lbh.algorithm;



import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

// 加签验签
public class Endorsement {

    //  加签
    public static String setSignature(String privateKeyStr,String param) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, InvalidKeySpecException {

        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec priPKCS8;
        priPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyStr));
        KeyFactory keyf = KeyFactory.getInstance("RSA");
        privateKey = keyf.generatePrivate(priPKCS8);

        // 实例化一个用SHA算法进行散列，用RSA算法进行加密的Signature.
        Signature dsa = Signature.getInstance("SHA1withRSA");
        // 加载加密散列码用的私钥
        dsa.initSign(privateKey);
        // 进行散列，对产生的散列码进行加密并返回
        dsa.update(param.getBytes());

        return Base64.encodeBase64String(dsa.sign());//进行签名
    }

    // 验签
    public static boolean checkTestSig(String publicKeyStr,String paramData,String signatureStr) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        PublicKey publicKey = null;
        X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(
                Base64.decodeBase64(publicKeyStr));
        KeyFactory keyFactory;
        keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(bobPubKeySpec);
        //d. 公钥进行验签
            //获取Signature实例，指定签名算法(与之前一致)
            Signature dsa = Signature.getInstance("SHA1withRSA");
            //加载公钥
            dsa.initVerify(publicKey);
            //更新原数据
            dsa.update(paramData.getBytes());

             //公钥验签（true-验签通过；false-验签失败）
            return dsa.verify(Base64.decodeBase64(signatureStr));//将签名数据从ase64编码字符串转回字节数组
    }
}
