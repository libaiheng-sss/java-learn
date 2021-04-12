package com.lbh.ss_sign;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.sql.SQLOutput;

public class Test {

    public static void main(String[] args) throws SignatureException, InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        String str = "appId=43AF047BBA47FC8A1AE8EFB232BDBBCB&data={\"appId\":\"43AF047BBA47FC8A1AE8EFB232BDBBCB\",\"appUserId\":\"o8z4C5avQXqC0aWFPf1Mzu6D7WCQ_bd\",\"idNo\":\"350181199011193519\",\"idType\":\"01\",\"phoneNumber\":\"13763873033\",\"userName\":\"测试\"}&encType=SM4&signType=SM2&timestamp=20200207175759&transType=ec.gen.index&version=1.0.0&key=4117E877F5FA0A0188891283E4B617D5";
        String s = GetSignData.GetSignData(str);
        System.out.println(s);
        boolean b = GetSignData.checkSignature(str, s);
        System.out.println(b);

        String key = "3AF047BBA47FC8A1AE8EFB232BDBBCB";
        String param = "libaiheng";
        System.out.println("原文:"+param);
        String encryptEcb = EncryptionAndCheck.encryptEcb(key, param);
        System.out.println("加密:"+encryptEcb);
        String decryptEcb = EncryptionAndCheck.decryptEcb(key, encryptEcb);
        System.out.println("解密:"+decryptEcb);
        boolean verifyEcb = EncryptionAndCheck.verifyEcb(key, encryptEcb, param);
        System.out.println("验证:"+verifyEcb);
    }
}
