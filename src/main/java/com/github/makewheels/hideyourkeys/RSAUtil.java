package com.github.makewheels.hideyourkeys;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAUtil {
    /**
     * 生成公私钥对
     *
     * @return
     */
    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (keyPairGenerator == null) {
            return null;
        }
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 秘钥转base64
     *
     * @param key
     * @return
     */
    public static String keyToBase64(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * 加密
     *
     * @param data
     * @param publicKey
     * @return
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static String encrypt(String data, PublicKey publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 解密
     *
     * @param data
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(String data, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(data)));
    }

    /**
     * 把本地key文件读出字符串
     *
     * @param keyFile
     * @return
     */
    private static String readKeyFile(File keyFile) {
        String base64String;
        try {
            base64String = FileUtils.readFileToString(keyFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        if (StringUtils.isEmpty(base64String))
            return null;
        base64String = base64String.replace(" ", "");
        base64String = base64String.replace("\r", "");
        base64String = base64String.replace("\n", "");
        base64String = base64String.replace("\t", "");
        return base64String;
    }

    /**
     * 加载本地公钥文件
     *
     * @param keyFile
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey loadPublicKey(File keyFile)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String base64String = readKeyFile(keyFile);
        if (StringUtils.isEmpty(base64String))
            return null;
        byte[] keyBytes = Base64.getDecoder().decode(base64String);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * 加载本地私钥文件
     *
     * @param keyFile
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKey(File keyFile)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String base64String = readKeyFile(keyFile);
        if (StringUtils.isEmpty(base64String))
            return null;
        byte[] keyBytes = Base64.getDecoder().decode(base64String);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    /**
     * 保存秘钥文件
     *
     * @param key
     * @param keyFile
     * @throws IOException
     */
    public static void saveKeyFile(Key key, File keyFile) throws IOException {
        String base64 = keyToBase64(key);
        FileUtils.writeStringToFile(keyFile, base64, StandardCharsets.UTF_8);
    }

}
