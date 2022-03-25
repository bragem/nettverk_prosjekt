package utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Util class for cryptography actions
 */
public class CryptoUtil {

    private static Logger logger = LoggerFactory.getLogger(CryptoUtil.class);


    /**
     * Returns a byte array containing the decrypted data
     *
     * @param encryptedData byte array of the encrypted data
     * @param length how many bytes in the array to decrypt from position 0
     * @param key the {@link SecretKey} that will be used to decrypt
     * @return byte array containing the decrypted data
     * @throws Exception if the key is invalid
     */
    public static byte[] decryptAES(byte[] encryptedData, int length, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(Base64.getDecoder()
                    .decode(encryptedData));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            logger.error(e.getMessage());
        }

        return new byte[]{};
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
    public static byte[] encryptAES(byte[] data, int length, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(data)).getBytes();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            logger.error(e.getMessage());
        }

        return new byte[]{};
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
    public static byte[] decryptRSA(byte[] data,int length, PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);

            return cipher.doFinal(data, 0, length);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            logger.error(e.getMessage());
        }

        return new byte[]{};
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
    public static byte[] encryptRSA(byte[] data,int length, PublicKey key){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, key);

            return cipher.doFinal(data, 0, length);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            logger.error(e.getMessage());
        }

        return new byte[]{};

    }


    /**
     * Creates a new private-public keypair of type RSA
     *
     * @throws NoSuchAlgorithmException if the generator doesn't recognize the encryption algorithm
     * @throws IOException if the saveRSA method fails to save the keys
     */
    public static void createRSA() throws IOException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);

            KeyPair kp = kpg.generateKeyPair();

            PublicKey pub = kp.getPublic();
            PrivateKey pvt = kp.getPrivate();
            saveRSA(pub, pvt);
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage());
        }

        //cleanUp(new File("./keys"));
    }

    /**
     * Saves a public and a private key to two different files
     *
     * @param pub the public key
     * @param pvt the private key
     * @throws IOException if it fails to save to file
     */
    public static void saveRSA(PublicKey pub, PrivateKey pvt) {
        String pubOutFile = "rsa_pub.pub";
        String pvtOutFile = "rsa_pvt.key";

        File dir = new File("./src/keys/");
        boolean dirCreated = dir.mkdir();

        if(dirCreated) {
            logger.info("Directory created");

            File rsaPub = new File("./src/keys/" + pubOutFile);
            File rsaPvt = new File("./src/keys/" + pvtOutFile);

            try(FileOutputStream fosPub = new FileOutputStream(rsaPub)) {
                fosPub.write(pub.getEncoded());
            } catch (IOException e) {
                logger.error(e.getMessage());
            }

            try(FileOutputStream fosPvt = new FileOutputStream(rsaPvt)) {
                fosPvt.write(pvt.getEncoded());
            } catch (IOException e) {
                logger.error(e.getMessage());
            }
        }
    }

    /**
     * Loads an RSA private key from file
     *
     * @return {@link PrivateKey}
     */
    public static PrivateKey loadRSAPrivateKey(String filePath) {

        try {
            Path path = Paths.get(filePath);
            byte[] bytes = Files.readAllBytes(path);

            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kf.generatePrivate(ks);

            return pvt;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
        }

        return null;
    }

    /**
     * Loads an RSA public key from file
     *
     * @return {@link PublicKey}
     */
    public static PublicKey loadRSAPublicKey(String filePath) {

        try {
            Path path = Paths.get(filePath);
            byte[] bytes = Files.readAllBytes(path);

            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(ks);

            return pub;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error(e.getMessage());
        }

        return null;
    }

    /**
     * Deletes the generated public- and private key files with its folder
     *
     * @param file the {@link File} with the path to the directory of the public and private keys
     * @return true if files and folders are deleted successfully, otherwise false
     */
    public static boolean cleanUp(File file) {
        File[] contents = file.listFiles();
        if (contents != null) {
            for (File f : contents) {
                if (!Files.isSymbolicLink(f.toPath())) {
                    cleanUp(f);
                }
            }
        }
        return file.delete();
    }
}
