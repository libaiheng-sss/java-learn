package com.lbh.algorithm;

import org.apache.commons.codec.binary.Base64;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

// 根据**.p12 文件获取私钥和公钥
public class GetKeyByP12File {

    private String keyStoreFilePath;  // 证书路径
    private String keyStorePassword;  // 证书密码
    private String keyStoreAlias;  // alias
    private static KeyStore keyStore = null;

    public GetKeyByP12File(String keyStoreFilePath, String keyStorePassword, String keyStoreAlias) throws KeyStoreException, IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException {
        this.keyStoreFilePath = keyStoreFilePath;
        this.keyStorePassword = keyStorePassword;
        this.keyStoreAlias = keyStoreAlias;
        get();
    }

    public String getPublicKey() throws KeyStoreException {
        Certificate cert = keyStore.getCertificate(keyStoreAlias);
        PublicKey pubkey = cert.getPublicKey();
        String publicKeyStr = Base64.encodeBase64String(pubkey.getEncoded());
        return publicKeyStr;
    }

    public String getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        PrivateKey prikey = (PrivateKey) keyStore.getKey(keyStoreAlias, keyStorePassword.toCharArray());
        String privateKeyStr = Base64.encodeBase64String(prikey.getEncoded());
        return privateKeyStr;
    }

    private void get() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
       // 实例化密钥库，默认JKS类型
        keyStore = KeyStore.getInstance("PKCS12");
        // 获得密钥库文件流
        FileInputStream fileInputStream = new FileInputStream(keyStoreFilePath);

        char[] nPasswd = null;
        nPasswd = keyStorePassword.toCharArray();
        keyStore.load(fileInputStream,nPasswd);
        fileInputStream.close();


        Enumeration<String> enum1 = keyStore.aliases();
        if (enum1.hasMoreElements()) {
            keyStoreAlias = (String)enum1.nextElement();
        }
    }
    }
