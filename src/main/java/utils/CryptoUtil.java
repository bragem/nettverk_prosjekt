package utils;

import javax.crypto.*;

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
    public static byte[] decrypt(byte[] encryptedData, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(encryptedData, 0, length);
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
    public static byte[] encrypt(byte[] data, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data, 0, length);
    }

}
