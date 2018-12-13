//package com.demo.rsademo;
//
//
//import java.io.BufferedReader;
//import java.io.ByteArrayOutputStream;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.InputStreamReader;
//import java.math.BigInteger;
//import java.security.*;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.RSAPublicKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//import java.util.HashMap;
//import java.util.Map;
//
//import javax.crypto.Cipher;
//
//public class RsaUtil {
////    private static String RSA = "RSA";
////
////    /**
////     * 随机生成RSA密钥对(默认密钥长度为1024)
////     *
////     * @return
////     */
////    public static KeyPair generateRSAKeyPair() {
////        return generateRSAKeyPair(1024);
////    }
////
////    /**
////     * 随机生成RSA密钥对
////     *
////     * @param keyLength 密钥长度，范围：512～2048
////     * @return
////     */
////    public static KeyPair generateRSAKeyPair(int keyLength) {
////        try {
////            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
////            kpg.initialize(keyLength);
////            return kpg.genKeyPair();
////        } catch (NoSuchAlgorithmException e) {
////            e.printStackTrace();
////            return null;
////        }
////    }
////
////    /**
////     * 用公钥加密 <br>
////     * 每次加密的字节数，不能超过密钥的长度值除以 8 再减去 11，所以采取分段加密的方式规避
////     *
////     * @param data      需加密数据的byte数据
////     * @param publicKey 公钥
////     * @return 加密后的byte型数据
////     */
////    public static byte[] encryptData(byte[] data, PublicKey publicKey) {
////        try {
////            Cipher cipher = Cipher.getInstance(RSA);
////            // 编码前设定编码方式及密钥
////            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
////
////            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
////            // 模长
////            int keyLen = rsaPublicKey.getModulus().bitLength() / 8;
////            int maxEncryptBlock = keyLen - 11;
////
////            //如果明文长度大于模长-11则要分组加密
////            int inputLen = data.length;
////            ByteArrayOutputStream out = new ByteArrayOutputStream();
////            int offSet = 0;
////            byte[] temp;
////            int i = 0;
////            // 对数据分段加密
////            while (inputLen - offSet > 0) {
////                if (inputLen - offSet > maxEncryptBlock) {
////                    temp = cipher.doFinal(data, offSet, maxEncryptBlock);
////                } else {
////                    temp = cipher.doFinal(data, offSet, inputLen - offSet);
////                }
////                out.write(temp, 0, temp.length);
////                i++;
////                offSet = i * maxEncryptBlock;
////            }
////            byte[] encryptedData = out.toByteArray();
////            out.close();
////            // 传入编码数据并返回编码结果
////            return encryptedData;
////        } catch (Exception e) {
////            e.printStackTrace();
////            return null;
////        }
////    }
////
////    /**
////     * 用私钥解密
////     *
////     * @param encryptedData 经过encryptedData()加密返回的byte数据
////     * @param privateKey    私钥
////     * @return
////     */
////    public static byte[] decryptData(byte[] encryptedData, PrivateKey privateKey) {
////        try {
////            Cipher cipher = Cipher.getInstance(RSA);
////            cipher.init(Cipher.DECRYPT_MODE, privateKey);
////
////            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
////            // 模长
////            int keyLen = rsaPrivateKey.getModulus().bitLength() / 8;
////            int maxDecryptBlock = keyLen;//不用减11
////
////            //如果密文长度大于模长则要分组解密
////            int inputLen = encryptedData.length;
////            ByteArrayOutputStream out = new ByteArrayOutputStream();
////            int offSet = 0;
////            byte[] temp;
////            int i = 0;
////            // 对数据分段解密
////            while (inputLen - offSet > 0) {
////                if (inputLen - offSet > maxDecryptBlock) {
////                    temp = cipher.doFinal(encryptedData, offSet, maxDecryptBlock);
////                } else {
////                    temp = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
////                }
////                out.write(temp, 0, temp.length);
////                i++;
////                offSet = i * maxDecryptBlock;
////            }
////            byte[] decryptedData = out.toByteArray();
////            out.close();
////
////            return decryptedData;
////        } catch (Exception e) {
////            e.printStackTrace();
////            return null;
////        }
////    }
////
////    /**
////     * 通过公钥byte[](publicKey.getEncoded())将公钥还原，适用于RSA算法
////     *
////     * @param keyBytes
////     * @return
////     * @throws NoSuchAlgorithmException
////     * @throws InvalidKeySpecException
////     */
////    public static PublicKey getPublicKey(byte[] keyBytes) throws NoSuchAlgorithmException,
////            InvalidKeySpecException {
////        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
////        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
////        PublicKey publicKey = keyFactory.generatePublic(keySpec);
////        return publicKey;
////    }
////
////    /**
////     * 通过私钥byte[]将私钥还原，适用于RSA算法
////     *
////     * @param keyBytes
////     * @return
////     * @throws NoSuchAlgorithmException
////     * @throws InvalidKeySpecException
////     */
////    public static PrivateKey getPrivateKey(byte[] keyBytes) throws NoSuchAlgorithmException,
////            InvalidKeySpecException {
////        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
////        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
////        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
////        return privateKey;
////    }
////
////    /**
////     * 使用N、e值还原公钥
////     *
////     * @param modulus
////     * @param publicExponent
////     * @return
////     * @throws NoSuchAlgorithmException
////     * @throws InvalidKeySpecException
////     */
////    public static PublicKey getPublicKey(String modulus, String publicExponent)
////            throws NoSuchAlgorithmException, InvalidKeySpecException {
////        BigInteger bigIntModulus = new BigInteger(modulus);
////        BigInteger bigIntPrivateExponent = new BigInteger(publicExponent);
////        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
////        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
////        PublicKey publicKey = keyFactory.generatePublic(keySpec);
////        return publicKey;
////    }
////
////    /**
////     * 使用N、d值还原私钥
////     *
////     * @param modulus
////     * @param privateExponent
////     * @return
////     * @throws NoSuchAlgorithmException
////     * @throws InvalidKeySpecException
////     */
////    public static PrivateKey getPrivateKey(String modulus, String privateExponent)
////            throws NoSuchAlgorithmException, InvalidKeySpecException {
////        BigInteger bigIntModulus = new BigInteger(modulus);
////        BigInteger bigIntPrivateExponent = new BigInteger(privateExponent);
////        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
////        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
////        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
////        return privateKey;
////    }
////
////    /**
////     * 从字符串中加载公钥
////     *
////     * @param publicKeyStr 公钥数据字符串
////     * @throws Exception 加载公钥时产生的异常
////     */
////    public static PublicKey loadPublicKey(String publicKeyStr) throws Exception {
////        try {
////            byte[] buffer = Base64Utils.decode(publicKeyStr);
////            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
////            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
////            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
////        } catch (NoSuchAlgorithmException e) {
////            throw new Exception("无此算法");
////        } catch (InvalidKeySpecException e) {
////            throw new Exception("公钥非法");
////        } catch (NullPointerException e) {
////            throw new Exception("公钥数据为空");
////        }
////    }
////
////    /**
////     * 从字符串中加载私钥<br>
////     * 加载时使用的是PKCS8EncodedKeySpec（PKCS#8编码的Key指令）。
////     *
////     * @param privateKeyStr
////     * @return
////     * @throws Exception
////     */
////    public static PrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
////        try {
////            byte[] buffer = Base64Utils.decode(privateKeyStr);
////            //X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
////            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
////            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
////            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
////        } catch (NoSuchAlgorithmException e) {
////            throw new Exception("无此算法");
////        } catch (InvalidKeySpecException e) {
////            throw new Exception("私钥非法");
////        } catch (NullPointerException e) {
////            throw new Exception("私钥数据为空");
////        }
////    }
////
////    /**
////     * 从文件中输入流中加载公钥
////     *
////     * @param in 公钥输入流
////     * @throws Exception 加载公钥时产生的异常
////     */
////    public static PublicKey loadPublicKey(InputStream in) throws Exception {
////        try {
////            return loadPublicKey(readKey(in));
////        } catch (IOException e) {
////            throw new Exception("公钥数据流读取错误");
////        } catch (NullPointerException e) {
////            throw new Exception("公钥输入流为空");
////        }
////    }
////
////    /**
////     * 从文件中加载私钥
////     *
////     * @param in
////     * @return 私钥
////     * @throws Exception
////     */
////    public static PrivateKey loadPrivateKey(InputStream in) throws Exception {
////        try {
////            return loadPrivateKey(readKey(in));
////        } catch (IOException e) {
////            throw new Exception("私钥数据读取错误");
////        } catch (NullPointerException e) {
////            throw new Exception("私钥输入流为空");
////        }
////    }
////
////    /**
////     * 读取密钥信息
////     *
////     * @param in
////     * @return
////     * @throws IOException
////     */
////    private static String readKey(InputStream in) throws IOException {
////        BufferedReader br = new BufferedReader(new InputStreamReader(in));
////        String readLine = null;
////        StringBuilder sb = new StringBuilder();
////        while ((readLine = br.readLine()) != null) {
////            if (readLine.charAt(0) == '-') {
////                continue;
////            } else {
////                sb.append(readLine);
////                sb.append('\r');
////            }
////        }
////
////        return sb.toString();
////    }
//
//    /** *//**
//     * 加密算法RSA
//     */
//    public static final String KEY_ALGORITHM = "RSA";
//
//    /** *//**
//     * 签名算法
//     */
//    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
//
//    /** *//**
//     * 获取公钥的key
//     */
//    private static final String PUBLIC_KEY = "RSAPublicKey";
//
//    /** *//**
//     * 获取私钥的key
//     */
//    private static final String PRIVATE_KEY = "RSAPrivateKey";
//
//    /** *//**
//     * RSA最大加密明文大小
//     */
//    private static final int MAX_ENCRYPT_BLOCK = 117;
//
//    /** *//**
//     * RSA最大解密密文大小
//     */
//    private static final int MAX_DECRYPT_BLOCK = 128;
//
//    /** *//**
//     * <p>
//     * 生成密钥对(公钥和私钥)
//     * </p>
//     *
//     * @return
//     * @throws Exception
//     */
//    public static Map<String, Object> genKeyPair() throws Exception {
//        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//        keyPairGen.initialize(1024);
//        KeyPair keyPair = keyPairGen.generateKeyPair();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
//        Map<String, Object> keyMap = new HashMap<String, Object>(2);
//        keyMap.put(PUBLIC_KEY, publicKey);
//        keyMap.put(PRIVATE_KEY, privateKey);
//        return keyMap;
//    }
//
//    /** *//**
//     * <p>
//     * 用私钥对信息生成数字签名
//     * </p>
//     *
//     * @param data 已加密数据
//     * @param privateKey 私钥(BASE64编码)
//     *
//     * @return
//     * @throws Exception
//     */
//    public static String sign(byte[] data, String privateKey) throws Exception {
//        byte[] keyBytes = Base64Utils.decode(privateKey);
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
//        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
//        signature.initSign(privateK);
//        signature.update(data);
//        return Base64Utils.encode(signature.sign());
//    }
//
//    /** *//**
//     * <p>
//     * 校验数字签名
//     * </p>
//     *
//     * @param data 已加密数据
//     * @param publicKey 公钥(BASE64编码)
//     * @param sign 数字签名
//     *
//     * @return
//     * @throws Exception
//     *
//     */
//    public static boolean verify(byte[] data, String publicKey, String sign)
//            throws Exception {
//        byte[] keyBytes = Base64Utils.decode(publicKey);
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        PublicKey publicK = keyFactory.generatePublic(keySpec);
//        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
//        signature.initVerify(publicK);
//        signature.update(data);
//        return signature.verify(Base64Utils.decode(sign));
//    }
//
//    /** *//**
//     * <P>
//     * 私钥解密
//     * </p>
//     *
//     * @param encryptedData 已加密数据
//     * @param privateKey 私钥(BASE64编码)
//     * @return
//     * @throws Exception
//     */
//    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)
//            throws Exception {
//        byte[] keyBytes = Base64Utils.decode(privateKey);
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.DECRYPT_MODE, privateK);
//        int inputLen = encryptedData.length;
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        int offSet = 0;
//        byte[] cache;
//        int i = 0;
//        // 对数据分段解密
//        while (inputLen - offSet > 0) {
//            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
//                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
//            } else {
//                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
//            }
//            out.write(cache, 0, cache.length);
//            i++;
//            offSet = i * MAX_DECRYPT_BLOCK;
//        }
//        byte[] decryptedData = out.toByteArray();
//        out.close();
//        return decryptedData;
//    }
//
//    /** *//**
//     * <p>
//     * 公钥解密
//     * </p>
//     *
//     * @param encryptedData 已加密数据
//     * @param publicKey 公钥(BASE64编码)
//     * @return
//     * @throws Exception
//     */
//    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)
//            throws Exception {
//        byte[] keyBytes = Base64Utils.decode(publicKey);
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key publicK = keyFactory.generatePublic(x509KeySpec);
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.DECRYPT_MODE, publicK);
//        int inputLen = encryptedData.length;
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        int offSet = 0;
//        byte[] cache;
//        int i = 0;
//        // 对数据分段解密
//        while (inputLen - offSet > 0) {
//            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
//                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
//            } else {
//                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
//            }
//            out.write(cache, 0, cache.length);
//            i++;
//            offSet = i * MAX_DECRYPT_BLOCK;
//        }
//        byte[] decryptedData = out.toByteArray();
//        out.close();
//        return decryptedData;
//    }
//
//    /** *//**
//     * <p>
//     * 公钥加密
//     * </p>
//     *
//     * @param data 源数据
//     * @param publicKey 公钥(BASE64编码)
//     * @return
//     * @throws Exception
//     */
//    public static byte[] encryptByPublicKey(byte[] data, String publicKey)
//            throws Exception {
//        byte[] keyBytes = Base64Utils.decode(publicKey);
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key publicK = keyFactory.generatePublic(x509KeySpec);
//        // 对数据加密
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, publicK);
//        int inputLen = data.length;
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        int offSet = 0;
//        byte[] cache;
//        int i = 0;
//        // 对数据分段加密
//        while (inputLen - offSet > 0) {
//            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
//                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
//            } else {
//                cache = cipher.doFinal(data, offSet, inputLen - offSet);
//            }
//            out.write(cache, 0, cache.length);
//            i++;
//            offSet = i * MAX_ENCRYPT_BLOCK;
//        }
//        byte[] encryptedData = out.toByteArray();
//        out.close();
//        return encryptedData;
//    }
//
//    /** *//**
//     * <p>
//     * 私钥加密
//     * </p>
//     *
//     * @param data 源数据
//     * @param privateKey 私钥(BASE64编码)
//     * @return
//     * @throws Exception
//     */
//    public static byte[] encryptByPrivateKey(byte[] data, String privateKey)
//            throws Exception {
//        byte[] keyBytes = Base64Utils.decode(privateKey);
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
//        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
//        cipher.init(Cipher.ENCRYPT_MODE, privateK);
//        int inputLen = data.length;
//        ByteArrayOutputStream out = new ByteArrayOutputStream();
//        int offSet = 0;
//        byte[] cache;
//        int i = 0;
//        // 对数据分段加密
//        while (inputLen - offSet > 0) {
//            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
//                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
//            } else {
//                cache = cipher.doFinal(data, offSet, inputLen - offSet);
//            }
//            out.write(cache, 0, cache.length);
//            i++;
//            offSet = i * MAX_ENCRYPT_BLOCK;
//        }
//        byte[] encryptedData = out.toByteArray();
//        out.close();
//        return encryptedData;
//    }
//
//    /** *//**
//     * <p>
//     * 获取私钥
//     * </p>
//     *
//     * @param keyMap 密钥对
//     * @return
//     * @throws Exception
//     */
//    public static String getPrivateKey(Map<String, Object> keyMap)
//            throws Exception {
//        Key key = (Key) keyMap.get(PRIVATE_KEY);
//        return Base64Utils.encode(key.getEncoded());
//    }
//
//    /** *//**
//     * <p>
//     * 获取公钥
//     * </p>
//     *
//     * @param keyMap 密钥对
//     * @return
//     * @throws Exception
//     */
//    public static String getPublicKey(Map<String, Object> keyMap)
//            throws Exception {
//        Key key = (Key) keyMap.get(PUBLIC_KEY);
//        return Base64Utils.encode(key.getEncoded());
//    }
//}
//
