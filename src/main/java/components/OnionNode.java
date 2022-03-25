package components;

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
import java.security.*;
import java.util.Arrays;
import java.util.List;

/**
 * Node class which encrypts, decrypts and sends messages back and forth
 */
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
        logger.info(String.format("Node started at %s:%s", getIPAddress(), getPort()));
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
    public void setupConnection() {
        try {
            serverSocket = new ServerSocket(port);

            Socket connection = serverSocket.accept();
            DataInputStream dis = new DataInputStream(new BufferedInputStream(connection.getInputStream()));
            DataOutputStream dos = new DataOutputStream(connection.getOutputStream());

            prevIP = connection.getRemoteSocketAddress().toString().split("[/:]")[1];
            prevPort = connection.getPort();

            logger.info(String.format("IP of connected device: %s", prevIP));

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
                    logger.info(String.format("Received from client: %s", tmp));
                    logger.info("Sending public key back to client...");

                    PublicKey pk = CryptoUtil.loadRSAPublicKey("./src/keys/rsa_pub.pub");
                    byte[] stBytes = pk.getEncoded();

                    dos.writeInt(stBytes.length);
                    dos.write(stBytes);
                    dos.flush();

                } else if(getSecretKey() == null) {
                    byte[] decrypted = CryptoUtil.decryptRSA(
                            bytes,
                            bytes.length,
                            CryptoUtil.loadRSAPrivateKey("./src/keys/rsa_pvt.key"));

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

                    logger.info(String.format("Received IP and Port of next device: %s:%s", nextIP, nextPort));

                    forwardData(connection, message);
                    setupComplete = true;
                }
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }

    }

    /**
     * Takes an already established connection and creates a second one, to receive from one and send on the other
     *
     * @param connection the {@link Socket} that is already created
     * @param firstMessage the first message to forward to the next node
     * @throws Exception
     */
    public void forwardData(Socket connection, String firstMessage) {
        boolean quit = false;

        try {
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
                        logger.info("Message to previous node encrypted");
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

                        break;
                    default:
                        logger.info("Something weird happened");
                }

            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }

    }


    public static void main(String[] args) throws Exception {
        List<String> argsList = Arrays.asList(args);

        if(argsList.contains("-p")) {
            int port = Integer.parseInt(argsList.get(argsList.indexOf("-p") + 1));
            OnionNode node = new OnionNode(port);
            CryptoUtil.createRSA();
            node.setupConnection();
            CryptoUtil.cleanUp(new File("./src/keys"));

        }

    }
}
