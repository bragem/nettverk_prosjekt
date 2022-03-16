package utils;

import javax.crypto.*;

public class CryptoUtil {


    /**
     * Returns a byte array containing the decrypted data
     *
     * @param encryptedData byte array of the encrypted data
     * @param length the length of the byte array containing the encrypted data
     * @param key the {@link SecretKey} that will be used to decrypt
     * @return byte array containing the decrypted data
     * @throws Exception if the key is invalid
     */
    public static byte[] decrypt(byte[] encryptedData, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(encryptedData, 0, length);
    }

}
