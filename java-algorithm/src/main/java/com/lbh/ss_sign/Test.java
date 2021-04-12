package com.lbh.ss_sign;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public class Test {

    public static void main(String[] args) throws SignatureException, InvalidKeyException {
        String str = "appId=43AF047BBA47FC8A1AE8EFB232BDBBCB&data={\"appId\":\"43AF047BBA47FC8A1AE8EFB232BDBBCB\",\"appUserId\":\"o8z4C5avQXqC0aWFPf1Mzu6D7WCQ_bd\",\"idNo\":\"350181199011193519\",\"idType\":\"01\",\"phoneNumber\":\"13763873033\",\"userName\":\"测试\"}&encType=SM4&signType=SM2&timestamp=20200207175759&transType=ec.gen.index&version=1.0.0&key=4117E877F5FA0A0188891283E4B617D5";
        String s = GetSignData.GetSignData(str);
        System.out.println(s);
        boolean b = GetSignData.checkSignature(str, s);
        System.out.println(b);
    }
}
