import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

public class OnionNode {

    // Network info of node
    private String hostName;
    private String IPAddress;
    private int port;

    // Public and private RSA keys for initial setup of connection
    private Key publicKey;
    private Key privateKey;

    // Secret symmetric key
    private SecretKey secretKey;

    public OnionNode(int port) throws UnknownHostException {
        this.hostName = InetAddress.getLocalHost().getHostName();
        this.IPAddress = InetAddress.getByName(InetAddress.getLocalHost().getHostName()).getHostAddress();
        this.port = port;

        System.out.println("Node starting...");
        System.out.println("Node started at " + this.getIPAddress() + " on port " + this.getPort());
    }

    public String getHostName() {
        return hostName;
    }

    public String getIPAddress() {
        return IPAddress;
    }

    public int getPort() {
        return port;
    }

    public String getPublicKey() {
        return publicKey.getFormat();
    }

    //TODO: Remove method below
    public String getPrivateKey() {
        return privateKey.getFormat();
    }

    private void setPublicKey(Key key) {
        this.publicKey = key;
    }

    private void setPrivateKey(Key key) {
        this.privateKey = key;
    }

    private void setSecretKey(SecretKey key) {
        this.secretKey = key;
    }

    private void createRSA() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        PublicKey pub = kp.getPublic();
        PrivateKey pvt = kp.getPrivate();
        saveRSA(pub, pvt);
    }

    private void saveRSA(PublicKey pub, PrivateKey pvt) throws IOException {
        String pubOutFile = "rsa_pub.pub";
        String pvtOutFile = "rsa_pvt.key";

        File dir = new File("./keys/");
        boolean dirCreated = dir.mkdir();

        if(dirCreated) {
            System.out.println("Directory created");

            File rsaPub = new File("./keys/" + pubOutFile);
            File rsaPvt = new File("./keys/" + pvtOutFile);

            try(FileOutputStream fosPub = new FileOutputStream(rsaPub)) {
                fosPub.write(pub.getEncoded());
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }

            try(FileOutputStream fosPvt = new FileOutputStream(rsaPvt)) {
                fosPvt.write(pvt.getEncoded());
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }
        }
    }

    private PrivateKey loadRSAPrivateKey() {

        try {
            Path path = Paths.get("./keys/rsa_pvt.key");
            byte[] bytes = Files.readAllBytes(path);

            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kf.generatePrivate(ks);

            return pvt;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e);
        }

        return null;
    }

    private PublicKey loadRSAPublicKey() {

        try {
            Path path = Paths.get("./keys/rsa_pub.pub");
            byte[] bytes = Files.readAllBytes(path);

            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(ks);

            return pub;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e);
        }

        return null;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        List<String> argsList = Arrays.asList(args);

        if(argsList.contains("-p")) {
            int port = Integer.parseInt(argsList.get(argsList.indexOf("-p") + 1));
            OnionNode node = new OnionNode(port);
            node.createRSA();

            /*System.out.println("Public key format: \n" + node.getPublicKey() + "\n\n");
            System.out.println("Private key format: \n" + node.getPrivateKey() + "\n\n");*/
        }

    }
}
