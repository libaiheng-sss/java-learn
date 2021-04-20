package com.lbh.ss_sign;


import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.*;
import java.util.stream.Collectors;

public class Test {

    public static void main(String[] args) throws SignatureException, InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
//        String str = "appId=43AF047BBA47FC8A1AE8EFB232BDBBCB&data={\"appId\":\"43AF047BBA47FC8A1AE8EFB232BDBBCB\",\"appUserId\":\"o8z4C5avQXqC0aWFPf1Mzu6D7WCQ_bd\",\"idNo\":\"350181199011193519\",\"idType\":\"01\",\"phoneNumber\":\"13763873033\",\"userName\":\"测试\"}&encType=SM4&signType=SM2&timestamp=20200207175759&transType=ec.gen.index&version=1.0.0&key=4117E877F5FA0A0188891283E4B617D5";
//        String s = GetSignData.GetSignData(str);
//        System.out.println(s);
//        boolean b = GetSignData.checkSignature(str, s);
//        System.out.println(b);
//
//        String key = "3AF047BBA47FC8A1AE8EFB232BDBBCB";
//        String param = "libaiheng";
//        System.out.println("原文:"+param);
//        String encryptEcb = EncryptionAndCheck.encryptEcb(key, param);
//        System.out.println("加密:"+encryptEcb);
//        String decryptEcb = EncryptionAndCheck.decryptEcb(key, encryptEcb);
//        System.out.println("解密:"+decryptEcb);
//        boolean verifyEcb = EncryptionAndCheck.verifyEcb(key, encryptEcb, param);
//        System.out.println("验证:"+verifyEcb);

        Map<String,String> map = new HashMap();
        map.put("zasdf", "1");
        map.put("zbsdf", "2");
        map.put("aaaa", "3");
        map.put("aaa", "4");
        map.put("abbbb", "4");
        map.put("abccc", "5");
        map.put("e", "6");
        map.put("y", "7");
        map.put("n", "8");
        map.put("g", "10");
        map.put("m", "10");
        map.put("f", "10");
        Map<String, String> result = map.entrySet().stream().sorted(Collections.reverseOrder(Map.Entry.comparingByKey((var1, var2)->{
            int var3 = var1.length();
            int var4 = var2.length();
            int var5 = var3 < var4 ? var3 : var4;

            for(int var6 = 0; var6 < var5; ++var6) {
                char var7 = var1.charAt(var6);
                char var8 = var2.charAt(var6);

                assert var7 <= 127 && var8 <= 127;

                if (var7 != var8) {
                    var7 = (char)toLower(var7);
                    var8 = (char)toLower(var8);
                    if (var7 != var8) {
                        return var7 - var8;
                    }
                }
            }

            return var3 - var4;
        }))).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                (oldValue, newValue) -> oldValue, LinkedHashMap::new));
        System.out.println(result);


    }
    static int toLower(int var0) {
        return isUpper(var0) ? var0 + 32 : var0;
    }
    static boolean isUpper(int var0) {
        return (var0 - 65 | 90 - var0) >= 0;
    }
}
