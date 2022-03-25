package utils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertTrue;


public class CryptoUtilTest {
    SecretKey secretKey;
    PublicKey publicKey;

    @BeforeEach
    void makeKeys() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        secretKey = kg.generateKey();
        publicKey = CryptoUtil.loadRSAPublicKey("./src/test/utils/keys/rsa_pub.pub");
    }

    @Test
    @DisplayName("User gets created successfully")
    void encryptingMessage(){
    }

}
