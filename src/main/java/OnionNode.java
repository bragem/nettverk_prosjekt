import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.CryptoUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class OnionNode {

    private static Logger logger = LoggerFactory.getLogger(OnionNode.class);

    // Network info of node
    private String IPAddress;
    private int port;

    // Secret symmetric key
    private SecretKey secretKey;

    // Sockets for communicating back and forth
    private ServerSocket serverSocket;
    private Socket socket;

    // IP and Port of device connected to this node
    private String prevIP;
    private int prevPort;

    // IP of the device that this node connects to
    private String nextIP;
    private int nextPort;

    /**
     * Creates a new {@link OnionNode} object
     *
     * @param port the port to start the node at
     * @throws UnknownHostException
     */
    public OnionNode(int port) throws UnknownHostException {
        this.IPAddress = InetAddress.getByName(InetAddress.getLocalHost().getHostName()).getHostAddress();
        this.port = port;

        logger.info("Node starting...");
        logger.info(String.format("Node started at {}:{}", getIPAddress(), getPort()));
    }

    public String getIPAddress() {
        return IPAddress;
    }

    public int getPort() {
        return port;
    }

    private void setSecretKey(SecretKey key) {
        this.secretKey = key;
    }

    private SecretKey getSecretKey() {
        return this.secretKey;
    }

    /**
     * Sets up a connection between itself and a client or another node
     *
     * @throws Exception
     */
    public void setupConnection() throws Exception {
        serverSocket = new ServerSocket(port);

        Socket connection = serverSocket.accept();
        DataInputStream dis = new DataInputStream(new BufferedInputStream(connection.getInputStream()));
        DataOutputStream dos = new DataOutputStream(connection.getOutputStream());

        prevIP = connection.getRemoteSocketAddress().toString().split("[/:]")[1];
        prevPort = connection.getPort();

        logger.info(String.format("IP of connected device: {}", prevIP));

        int byteLength;
        byte[] bytes;
        String received;
        boolean setupComplete = false;

        while(!setupComplete) {

            byteLength = dis.readInt();
            bytes = new byte[byteLength];
            dis.readFully(bytes);

            String tmp = new String(bytes, StandardCharsets.UTF_8);


            if("GivePK!!!".equals(tmp)) {
                logger.info(String.format("Received from client: {}", tmp));
                logger.info("Sending public key back to client...");

                PublicKey pk = loadRSAPublicKey();
                byte[] stBytes = pk.getEncoded();

                dos.writeInt(stBytes.length);
                dos.write(stBytes);
                dos.flush();

            } else if(getSecretKey() == null) {
                byte[] decrypted = CryptoUtil.decryptRSA(bytes, bytes.length, loadRSAPrivateKey());

                SecretKey sk = new SecretKeySpec(decrypted, "AES");
                setSecretKey(sk);

                logger.info("Secret key received from client");

                String response = "Secret key set at node " + getIPAddress() + ":" + getPort();
                byte[] responseBytes = response.getBytes();
                byte[] encrypted = CryptoUtil.encryptAES(responseBytes, responseBytes.length, getSecretKey());

                dos.writeInt(encrypted.length);
                dos.write(encrypted);
                dos.flush();
            } else {
                byte[] decrypted = CryptoUtil.decryptAES(bytes, bytes.length, getSecretKey());
                String st = new String(decrypted, StandardCharsets.UTF_8);

                nextIP = st.split("[:/]")[0];
                nextPort = Integer.parseInt(st.split("[:/]")[1]);
                String message = st.split("[:/]")[2];

                logger.info(String.format("Received IP and Port of next device: {}:{}", nextIP, nextPort));

                forwardData(connection, message);
                setupComplete = true;
            }
        }

    }

    /**
     * Takes an already established connection and creates a second one, to receive from one and send on the other
     *
     * @param connection the {@link Socket} that is already created
     * @param firstMessage the first message to forward to the next node
     * @throws Exception
     */
    public void forwardData(Socket connection, String firstMessage) throws Exception {

        boolean quit = false;
        DataInputStream readFromPrev = new DataInputStream(new BufferedInputStream(connection.getInputStream()));
        DataOutputStream writeToPrev = new DataOutputStream((connection.getOutputStream()));

        socket = new Socket(nextIP, nextPort);
        DataInputStream readFromNext = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        DataOutputStream writeToNext = new DataOutputStream((socket.getOutputStream()));


        writeToNext.writeInt(firstMessage.getBytes().length);
        writeToNext.write(firstMessage.getBytes());
        writeToNext.flush();
        logger.info("First message to next node now sent");

        String lastAction = "writeToNext";

        int byteLength = 0;
        byte[] bytes = null;
        byte[] encrypted = null;
        byte[] decrypted = null;


        while(!quit) {

            switch(lastAction){
                case "writeToNext":
                    //trenger sjekk om det står quit eller teardown i meldinga
                    lastAction = "readFromNext";

                    byteLength = readFromNext.readInt();
                    bytes = new byte[byteLength];
                    readFromNext.readFully(bytes);

                    logger.info("Received message from next node");

                    break;
                case "readFromNext":
                    lastAction = "writeToPrev";

                    encrypted = CryptoUtil.encryptAES(bytes, bytes.length, getSecretKey());
                    logger.info("Message to previous node encrypted!");
                    writeToPrev.writeInt(encrypted.length);
                    writeToPrev.write(encrypted);
                    logger.info("Message to previous node sent");

                    break;
                case "writeToPrev":
                    lastAction = "readFromPrev";

                    byteLength = readFromPrev.readInt();
                    bytes = new byte[byteLength];
                    readFromPrev.readFully(bytes);

                    logger.info("Received message from previous node");

                    break;
                case "readFromPrev":
                    lastAction = "writeToNext";

                    decrypted = CryptoUtil.decryptAES(bytes, bytes.length, getSecretKey());
                    logger.info("Message to next node decrypted");
                    writeToNext.writeInt(decrypted.length);
                    writeToNext.write(decrypted);
                    logger.info("Message to next node sent");
                    System.out.println();

                    break;
                default:
                    logger.info("Something weird happened");
            }

        }

    }


    /**
     * Creates a new private-public keypair of type RSA
     *
     * @throws NoSuchAlgorithmException if the generator doesn't recognize the encryption algorithm
     * @throws IOException if the saveRSA method fails to save the keys
     */
    private void createRSA() throws IOException {
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
    private void saveRSA(PublicKey pub, PrivateKey pvt) {
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
    private PrivateKey loadRSAPrivateKey() {

        try {
            Path path = Paths.get("./src/keys/rsa_pvt.key");
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
    private PublicKey loadRSAPublicKey() {

        try {
            Path path = Paths.get("./src/keys/rsa_pub.pub");
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
    private boolean cleanUp(File file) {
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

    public static void main(String[] args) throws Exception {
        List<String> argsList = Arrays.asList(args);

        if(argsList.contains("-p")) {
            int port = Integer.parseInt(argsList.get(argsList.indexOf("-p") + 1));
            OnionNode node = new OnionNode(port);
            node.createRSA();
            node.setupConnection();
            node.cleanUp(new File("./src/keys"));

        }

    }
}
