package components;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.CryptoUtil;

/**
 * Client Class to choose amount of nodes to connect to and talk with server
 */
public class OnionClient {

    private static Logger logger = LoggerFactory.getLogger(OnionClient.class);

    DataInputStream reader;
    DataOutputStream writer;

    private int nrOfNodes;
    private int[] portsToVisit;
    private String[] inetAddresses;
    private Socket socket;
    String endIP;
    int endPort;

    private SecretKey[] secretKeys;
    private PublicKey[] publicKeys;

    /**
     * Constructor of {@link OnionNode} which takes in ip and port of the server it wants to connect to
     * Creates all symmetric keys upon creation
     * @param nrOfNodes number of nodes the client desires
     * @param ip ip of the server
     * @param endPort port of the server
     * @throws NoSuchAlgorithmException When {@link KeyGenerator} throws NoSuchAlgorithmException
     */
    public OnionClient(int nrOfNodes, String ip, int endPort) throws NoSuchAlgorithmException {
        this.socket = new Socket();
        this.endIP = ip;
        this.endPort = endPort;
        this.nrOfNodes = nrOfNodes;
        this.secretKeys = new SecretKey[nrOfNodes];
        this.publicKeys = new PublicKey[nrOfNodes];
        this.portsToVisit = new int[nrOfNodes+1];
        this.inetAddresses = new String[nrOfNodes+1];
        createSymmetricKeys();
    }

    /**
     * Reads in and sets all node ip and ports from a file.
     * In an ideal online solution this is fetched from a directory node, but here we considered it unecessary
     * work to implement, as we always get different ips on the school network
     * @throws IOException when {@link BufferedReader} throws IOException
     */
    public void setNodeDestinations() throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader("src/main/java/ipnports.txt"))) {
            String line;
            int i = 0;
            ArrayList<String> tmp = new ArrayList<>();

            while ((line = br.readLine()) != null) {
                String[] split = line.split(":");

                inetAddresses[i] = split[0];
                portsToVisit[i] = Integer.parseInt(split[1]);

                tmp.add(String.format("%s:%s", inetAddresses[i], portsToVisit[i]));
                i++;
            }

            logger.info(String.format("IP addresses and ports to visit %s", tmp));

            inetAddresses[i] = endIP;
            portsToVisit[i] = endPort;

            this.socket = new Socket(inetAddresses[0], portsToVisit[0]);
            reader = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            writer = new DataOutputStream(socket.getOutputStream());

        } catch (IOException e) {
            logger.error(e.getMessage());
        }

    }

    /**
     * Creates as many secret keys as nodes the user wants to connect to
     * @throws NoSuchAlgorithmException When {@link KeyGenerator} throws NoSuchAlgorithmException
     */
    private void createSymmetricKeys() throws NoSuchAlgorithmException {
        for(int i = 0; i < nrOfNodes; i++) {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            secretKeys[i] = kg.generateKey();
        }
    }


    /**
     * Starts the setup, and when it is complete loops through and sends and recieves messages from server
     * @throws Exception alot of places, just dont fuck it up
     */
    private void run() throws Exception {
        setup();
        logger.info("Setup complete");

        System.out.println("\n\nPlease write your message, enter when finished.");
        System.out.println("Enter 'quit' without the quotes, or just enter to exit the program");

        while (true) {
            System.out.println("Write your message: ");
            BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
            String msg = read.readLine();

            //Ending connection that is established
            if (msg == null || msg.trim().equalsIgnoreCase("quit")){
                logger.warn("Shutting down...");
                msg = "quit";
                byte[] shutdownBytes = shutDown(msg.getBytes());
                writer.writeInt(shutdownBytes.length);
                writer.write(shutdownBytes);
                logger.info("Shutdown complete");
                read.close();
                break;
            }

            //Sending messages and encrypting them
            byte[] byteMessage = msg.getBytes(StandardCharsets.UTF_8);

            logger.info("Message being encrypted");
            logger.info("Message being sent");

            byte[] encryptMessage = encryptMessage(byteMessage);
            writer.writeInt(encryptMessage.length);
            writer.write(encryptMessage);
            logger.info(String.format("Message sent: %s", msg));

            //Receiving messages and decrypting them

            byte[] bytesReceive = new byte[reader.readInt()];
            reader.readFully(bytesReceive);
            for (int j = 0; j < nrOfNodes; j++) {
                bytesReceive = CryptoUtil.decryptAES(bytesReceive, bytesReceive.length, secretKeys[j]);
            }
            String fromServer = new String(bytesReceive, StandardCharsets.UTF_8);

            logger.info(String.format("Message from server: %s", fromServer));

        }
        reader.close();
        writer.close();

        socket.close();
    }

    /**
     * Setup establishes connection between client and its nodes
     * @throws Exception thrown when {@link DataInputStream},{@link DataOutputStream} fails
     */
    public void setup() throws Exception {
        logger.info("Starting setup...");
        String msg = "GivePK!!!";
        for (int i = 0; i < nrOfNodes; i++) {
            //Public key is first received from using the method askForKey for the first node, then
            //we use connectSetup method to get public keys for the rest of the nodes.
            if (i == 0){
                //public key for first node is received
                publicKeys[0] = firstNodeKey(msg);
                byte[] secretKey = CryptoUtil.encryptRSA(secretKeys[0].getEncoded(), secretKeys[0].getEncoded().length, publicKeys[0]);
                //secret key is encrypted in the public key received and is sent
                writer.writeInt(secretKey.length);
                writer.write(secretKey);
                //confirmation is received from the first node
                byte[] confirmation = new byte[reader.readInt()];
                reader.readFully(confirmation);
                confirmation = CryptoUtil.decryptAES(confirmation, confirmation.length, secretKeys[0]);
                logger.info(new String(confirmation, StandardCharsets.UTF_8));
            }
            else {
                //public key for first node is received
                publicKeys[i] = getPublicKey(i, msg);
                //logger.info(String.format("public key received from node %s", i));

                byte[] secretKey = CryptoUtil.encryptRSA(secretKeys[i].getEncoded(), secretKeys[i].getEncoded().length, publicKeys[i]);
                //secret key encrypted in prev node secret keys and is sent
                secretKey = encryptSecretKey(i,secretKey);
                writer.writeInt(secretKey.length);
                writer.write(secretKey);

                //logger.info(String.format("secret key sent"));

                //confirmation is received from nodes and decrypted
                byte[] confirmation = new byte[reader.readInt()];

                //logger.info(String.format("confirmation received from node %s", i));

                reader.readFully(confirmation);
                for (int j = 0; j <= i; j++) {
                    //logger.info(String.format("node %s decrypted", (j+1)));

                    confirmation = CryptoUtil.decryptAES(confirmation, confirmation.length, secretKeys[j]);
                }

                logger.info(new String(confirmation, StandardCharsets.UTF_8));
            }
        }
    }

    /**
     * method to communicate with the first node and ask for key
     * @param msg message for the node
     * @return returns the public key of the first node
     * @throws IOException thrown when {@link DataInputStream},{@link DataOutputStream} fails
     * @throws NoSuchAlgorithmException thrown when {@link KeyFactory} has failed
     * @throws InvalidKeySpecException thrown when  {@link KeyFactory} generation of public key fails
     */
    public PublicKey firstNodeKey(String msg) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] askForKeyBytes = msg.getBytes();
        writer.writeInt(askForKeyBytes.length);
        writer.write(askForKeyBytes);

        int l = reader.readInt();
        byte[] decrypted = new byte[l];
        reader.readFully(decrypted);

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decrypted);
        return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    }

    /**
     * This method encrypts the message to the desired node in the secret keys obtained from nodes before it
     * @param i node we are asking the public key for now
     * @param msg message to the node we want key from
     * @return public key from the node
     * @throws Exception thrown when {@link CryptoUtil} decrypting or encrypting
     */
    private PublicKey getPublicKey(int i, String msg) throws Exception{
        //encrypt secret keys
        byte[] secretKeyByte = secretKeys[i-1].getEncoded();
        byte[] cryptData = CryptoUtil.encryptRSA(secretKeyByte, secretKeyByte.length, publicKeys[i-1]);
        byte[] msgBytes = msg.getBytes();

        ByteBuffer buffer;
        for (int j = i - 1 ; j >= 0; j--) {
            if (j== i-1) {
                buffer = ByteBuffer.allocate((inetAddresses[j + 1]).getBytes().length
                        + String.valueOf(portsToVisit[j + 1]).getBytes().length
                        + ":".getBytes().length
                        + "/".getBytes().length
                        + msgBytes.length);

                //logger.info(String.format("%s:%s", inetAddresses[j + 1], portsToVisit[j + 1]));

                buffer.put((inetAddresses[j + 1]).getBytes());
                buffer.put((byte) ':');
                buffer.put(String.valueOf(portsToVisit[j + 1]).getBytes());
                buffer.put((byte) '/');
                buffer.put(msgBytes);

                cryptData = new byte[(inetAddresses[j + 1]).getBytes().length
                        + String.valueOf(portsToVisit[j + 1]).getBytes().length
                        + ":".getBytes().length
                        + "/".getBytes().length
                        + msg.getBytes().length];
                buffer.flip();
                buffer.get(cryptData);
            }
            cryptData = CryptoUtil.encryptAES(cryptData, cryptData.length, secretKeys[j]);
        }

        writer.writeInt(cryptData.length);
        writer.write(cryptData);

        int l = reader.readInt();
        byte[] decrypted = new byte[l];
        reader.readFully(decrypted);


        for (int j = 0; j < i; j++) {
            decrypted = CryptoUtil.decryptAES(decrypted, l, secretKeys[j]);
        }

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decrypted);
        return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    }

    /**
     * This method encrypts the secret key we are sending the desired node with its other nodes secret key
     * @param nowNode node we want to give the secret key to
     * @param msg message (secret key) for the node
     * @return byte array of the complete encrypted message to reach the desired node
     * @throws Exception thrown when  {@link CryptoUtil} encrypting
     */
    public byte[] encryptSecretKey(int nowNode, byte[] msg) throws Exception {
        byte[] byteMessage = Arrays.copyOf(msg, msg.length);
        // encryption
        for (int i = nowNode; i >= 0; i--) {
            ByteBuffer buffer;
            if((i != nowNode)){
                //placing the message inside a bytebuffer, so it is clear how the message is structured
                buffer = ByteBuffer.allocate(byteMessage.length);
                buffer.put(byteMessage);
                buffer.flip();

                byteMessage = new byte[buffer.limit()];
                buffer.get(byteMessage);

                byteMessage = CryptoUtil.encryptAES(byteMessage, byteMessage.length, secretKeys[i]);
            }
            else {
                //raw msg for final destination
                buffer = ByteBuffer.allocate(byteMessage.length);

                buffer.put(byteMessage);
                buffer.flip();

                byteMessage = new byte[buffer.limit()];
                buffer.get(byteMessage);
            }
        }
        return byteMessage;
    }

    /**
     * Method that is used for encryption when talking to server
     * @param msg message to encrypt, in the form of a bytearray
     * @return encrypted bytearray
     * @throws Exception when {@link CryptoUtil}.encryptAES throws an exception
     */
    public byte[] encryptMessage(byte[] msg) throws Exception {
        byte[] msgBytes = Arrays.copyOf(msg, msg.length);

        for (int i = nrOfNodes-1; i >= 0; i--) {
            ByteBuffer byteBuffer;
            //ip and end port of server is encrypted in the loop
            if (i == nrOfNodes-1) {
                byteBuffer = ByteBuffer.allocate(msgBytes.length
                );
                byteBuffer.put(msgBytes);
                byteBuffer.flip();
                msgBytes = new byte[byteBuffer.limit()];
                byteBuffer.get(msgBytes);
            }
            msgBytes = CryptoUtil.encryptAES(msgBytes, msgBytes.length, secretKeys[i]);
        }
        return msgBytes;
    }

    /**
     * Method that is used for encryption when talking to server now msg is 0 for shutting down
     * @param msg message to encrypt, in the form of a bytearray
     * @return encrypted bytearray
     * @throws Exception when {@link CryptoUtil}.encryptAES throws an exception
     */
    public byte[] shutDown(byte[] msg) throws Exception {
        byte[] msgBytes = Arrays.copyOf(msg, msg.length);

        for (int i = nrOfNodes-1; i >= 0; i--) {
            ByteBuffer byteBuffer;
            //ip and end port of server is encrypted in the loop
            if (i == nrOfNodes-1) {
                byteBuffer = ByteBuffer.allocate(msgBytes.length);
                byteBuffer.put(msgBytes);
                byteBuffer.flip();
                msgBytes = new byte[byteBuffer.limit()];
                byteBuffer.get(msgBytes);

            }
            msgBytes = CryptoUtil.encryptAES(msgBytes, msgBytes.length, secretKeys[i]);
        }
        return msgBytes;
    }

    public static void main(String[] args) throws Exception {
        int tempNodes = 4;
        OnionClient onionClient = new OnionClient(tempNodes, "localhost", 8119);
        onionClient.setNodeDestinations();
        onionClient.run();
    }
}
