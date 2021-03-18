package com.github.makewheels.hideyourkeys;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.PropertiesConfigurationLayout;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.SystemUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

/**
 * @Author makewheels
 * @Time 2021.03.16 22:01:00
 */
@Slf4j
public class SecretKeyUtil {
    private static String applicationName;

    /**
     * 获取配置文件中的应用名
     *
     * @return
     */
    private static String getApplicationName() {
        if (applicationName != null)
            return applicationName;
        PropertiesConfiguration config = new PropertiesConfiguration();
        PropertiesConfigurationLayout layout = config.getLayout();
        File propertiesFile = new File(SecretKeyUtil.class
                .getResource("/application.properties").getPath());
        try {
            layout.load(config, new FileReader(propertiesFile));
        } catch (ConfigurationException | FileNotFoundException e) {
            e.printStackTrace();
        }
        return config.get(String.class, "spring.application.name");
    }

    /**
     * 替换单个配置文件
     *
     * @param propertiesFile
     * @param privateKey
     */
    private static void handleSingleFile(File propertiesFile, PrivateKey privateKey)
            throws IOException, ConfigurationException {
        log.info("key replace file: {}", propertiesFile.getName());
        PropertiesConfiguration config = new PropertiesConfiguration();
        PropertiesConfigurationLayout layout = config.getLayout();
        layout.load(config, new FileReader(propertiesFile));
        List<String> keys = IteratorUtils.toList(config.getKeys());
        keys.stream().filter(key -> {
            if (StringUtils.isEmpty(key))
                return false;
            String value = config.get(String.class, key);
            return StringUtils.isNotEmpty(value);
        }).forEach(key -> {
            //找到加密字段，解密替换
            String prefix = "CIPHER";
            String value = config.get(String.class, key);
            if (value.startsWith(prefix)) {
                value = value.replaceFirst(prefix, "");
                String decrypt;
                try {
                    decrypt = RSAUtil.decrypt(value, privateKey);
                } catch (NoSuchPaddingException | NoSuchAlgorithmException
                        | InvalidKeyException | BadPaddingException
                        | IllegalBlockSizeException e) {
                    e.printStackTrace();
                    return;
                }
                config.setProperty(key, decrypt);
                log.info("replace key: {}", key);
            }
        });
        //最后保存文件
        layout.save(config, new FileWriter(propertiesFile, false));
    }

    /**
     * 获取存秘钥文件的根目录
     *
     * @return
     */
    public static File getKeyFolder() {
        return new File(SystemUtils.getUserHome(), "keys");
    }

    private static File getPrivateKeyFile() {
        return new File(getKeyFolder(), getApplicationName() + ".privateKey");
    }

    private static File getPublicKeyFile() {
        return new File(getKeyFolder(), getApplicationName() + ".publicKey");
    }

    /**
     * 加载本地私钥
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String applicationName = getApplicationName();
        if (StringUtils.isEmpty(applicationName))
            return null;
        File keyFile = getPrivateKeyFile();
        if (!keyFile.exists()) {
            log.info("secret key not exist: {}", keyFile.getPath());
            return null;
        }
        return RSAUtil.loadPrivateKey(keyFile);
    }

    /**
     * 加载本地公钥
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey loadPublicKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String applicationName = getApplicationName();
        if (StringUtils.isEmpty(applicationName))
            return null;
        File keyFile = new File(getKeyFolder(), applicationName + ".publicKey");
        if (!keyFile.exists()) {
            log.info("public key not exist: {}", keyFile.getPath());
            return null;
        }
        return RSAUtil.loadPublicKey(keyFile);
    }

    /**
     * 保存公钥到本地
     *
     * @param publicKey
     */
    public static void savePublicKey(PublicKey publicKey) {
        File publicKeyFile = getPublicKeyFile();
        if (publicKeyFile.exists()) {
            log.warn("public key file already exist, will over write it, key file path:");
            log.warn(publicKeyFile.getPath());
        }
        try {
            RSAUtil.saveKeyFile(publicKey, publicKeyFile);
            log.info("save new public key file: {}", publicKeyFile.getPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 保存私钥到本地
     *
     * @param privateKey
     */
    public static void savePrivateKey(PrivateKey privateKey) {
        File privateKeyFile = getPrivateKeyFile();
        if (privateKeyFile.exists()) {
            log.warn("private key file already exist, will over write it, key file path:");
            log.warn(privateKeyFile.getPath());
        }
        try {
            RSAUtil.saveKeyFile(privateKey, privateKeyFile);
            log.info("save new private key file: {}", privateKeyFile.getPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 暴露方法，复写本地keys
     */
    public static void overrideKeys() {
        //列出所有文件
        File[] files = new File(SecretKeyUtil.class.getResource("/").getPath()).listFiles();
        if (files == null)
            return;

        //加载本地私钥文件
        PrivateKey privateKey;
        try {
            privateKey = loadPrivateKey();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return;
        }
        if (privateKey == null)
            return;

        //遍历所有配置文件，逐一替换
        Arrays.stream(files).filter(file -> {
            if (!file.exists())
                return false;
            String fileName = file.getName();
            if (StringUtils.isEmpty(fileName))
                return false;
            return fileName.startsWith("application") && fileName.endsWith(".properties");
        }).forEach(file -> {
            try {
                handleSingleFile(file, privateKey);
            } catch (IOException | ConfigurationException e) {
                e.printStackTrace();
            }
        });
    }
}
