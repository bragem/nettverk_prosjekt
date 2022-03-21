import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
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

    private ServerSocket serverSocket;
    private Socket socket;

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

    public void setupConnection() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        serverSocket = new ServerSocket(port);

        Socket connection = serverSocket.accept();
        DataInputStream dis = new DataInputStream(new BufferedInputStream(connection.getInputStream()));

        int byteLength = 0;
        byte[] theBytes;
        String received;

        while(true) {
            byteLength = dis.readInt();
            theBytes = new byte[byteLength];
            dis.readFully(theBytes);

            System.out.println(theBytes.length);
            received = new String(theBytes, StandardCharsets.UTF_8);
            System.out.println("Recieved from client: " + received + "\n");
            System.out.println("Sending public key back to client\n");

            PublicKey pk = loadRSAPublicKey();

            DataOutputStream dos = new DataOutputStream(connection.getOutputStream());
            byte[] stBytes = pk.getEncoded();

            dos.writeInt(stBytes.length);
            dos.write(stBytes);
            dos.flush();

            byteLength = dis.readInt();
            theBytes = new byte[byteLength];
            dis.readFully(theBytes);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, loadRSAPrivateKey());

            byte[] decrypted = cipher.doFinal(theBytes);

            SecretKey sk = new SecretKeySpec(decrypted, "AES");
            System.out.println(Arrays.toString(sk.getEncoded()));

            received = new String(sk.getEncoded(), StandardCharsets.UTF_8);
            System.out.println("\nRecieved from client: " + received + "\n");


            if(secretKey != null) {
                break;
            }
        }

    }


    public void forwardData(String ip, int port) throws IOException {
        socket = new Socket(ip, port);

    }


    /**
     * Creates a new private-public keypair of type RSA
     *
     * @throws NoSuchAlgorithmException if the generator doesn't recognize the encryption algorithm
     * @throws IOException if the saveRSA method fails to save the keys
     */
    private void createRSA() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        PublicKey pub = kp.getPublic();
        PrivateKey pvt = kp.getPrivate();
        saveRSA(pub, pvt);
        //cleanUp(new File("./keys"));
    }

    /**
     * Saves a public and a private key to two different files
     *
     * @param pub the public key
     * @param pvt the private key
     * @throws IOException if it fails to save to file
     */
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

    private void cleanUp(File file) {
        File[] contents = file.listFiles();
        if (contents != null) {
            for (File f : contents) {
                if (!Files.isSymbolicLink(f.toPath())) {
                    cleanUp(f);
                }
            }
        }
        file.delete();
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        List<String> argsList = Arrays.asList(args);

        if(argsList.contains("-p")) {
            int port = Integer.parseInt(argsList.get(argsList.indexOf("-p") + 1));
            OnionNode node = new OnionNode(port);
            //node.createRSA();
            node.setupConnection();



            /*System.out.println("Public key format: \n" + node.getPublicKey() + "\n\n");
            System.out.println("Private key format: \n" + node.getPrivateKey() + "\n\n");*/
        }

    }
}
