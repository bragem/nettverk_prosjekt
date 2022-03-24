package utils;

import javax.crypto.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class CryptoUtil {


    /**
     * Returns a byte array containing the decrypted data
     *
     * @param encryptedData byte array of the encrypted data
     * @param length how many bytes in the array to decrypt from position 0
     * @param key the {@link SecretKey} that will be used to decrypt
     * @return byte array containing the decrypted data
     * @throws Exception if the key is invalid
     */
    public static byte[] decryptAES(byte[] encryptedData, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(Base64.getDecoder()
                .decode(encryptedData));
    }


    /**
     * Returns a byte array containing the encrypted data
     *
     * @param data byte array of the data to encrypt
     * @param length how many bytes in the array to encrypt from position 0
     * @param key the {@link SecretKey} to use to encrypt
     * @return byte array
     * @throws Exception if the key is invalid
     */
    public static byte[] encryptAES(byte[] data, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder()
                .encodeToString(cipher.doFinal(data)).getBytes();
    }

    /**
     * Returns a byte array containing the decrypted data
     *
     * @param data byte array of the data to decrypt
     * @param length how many bytes in the array to decrypt from position 0
     * @param key the {@link PrivateKey} to use to decrypt
     * @return byte array
     * @throws Exception if the key is invalid
     */
    public static byte[] decryptRSA(byte[] data,int length, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(data, 0, length);
    }

    /**
     * Returns a byte array containing the encrypted data
     *
     * @param data byte array of the data to encrypt
     * @param length how many bytes in the array to encrypt from position 0
     * @param key the {@link PublicKey} to use to encrypt
     * @return byte array
     * @throws Exception if the key is invalid
     */
    public static byte[] encryptRSA(byte[] data,int length, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data, 0, length);
    }

}
