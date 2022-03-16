package utils;

import javax.crypto.*;

public class CryptoUtil {

    public static byte[] decrypt(byte[] encryptedData, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(encryptedData, 0, length);
    }

}
