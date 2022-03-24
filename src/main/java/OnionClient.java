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
import java.util.Arrays;

import utils.CryptoUtil;

/**
 * Client Class to choose amount of nodes to connect to and talk with server
 */
public class OnionClient {

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
    public void setDest() throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader("src/main/java/ipnports.txt"))) {
            String line = br.readLine();
            int i = 0;
            while (line != null) {
                String[] split = line.split(":");
                inetAddresses[i] = split[0];
                portsToVisit[i] = Integer.parseInt(split[1]);
                line = br.readLine();
                System.out.println(inetAddresses[i] + ":" + portsToVisit[i]);
                i++;
            }

            inetAddresses[i] = endIP;
            portsToVisit[i] = endPort;
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.socket = new Socket(inetAddresses[0], portsToVisit[0]);
        reader = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        writer = new DataOutputStream(socket.getOutputStream());
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
        System.out.println("Receiving public key from node...");
        getPublicKey();
        System.out.println("Setup complete");

        System.out.println("\n\nPlease write your message, enter when finished.");
        System.out.println("Enter '0' without the quotes to exit the program");

        while (true) {
            System.out.println("Write your message: ");
            BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
            String msg = read.readLine();

            //Ending connection that is established
            if (msg == null || msg.trim().equalsIgnoreCase("0")){
                System.out.println("Shutting down...");

                System.out.println("Shutdown complete.");
                break;
            }

            //Sending messages and encrypting them
            byte[] byteMessage = msg.getBytes(StandardCharsets.UTF_8);

            System.out.println("Message being sent");
            System.out.println("Message being encrypted");

            byte[] encryptMessage = encryptMessage(byteMessage);
            writer.writeInt(encryptMessage.length);
            writer.write(encryptMessage);
            System.out.println("Message sent: " + msg + "\n");

            //Receiving messages and decrypting them
            System.out.println("Message from server: ");
            byte[] bytesReceive = new byte[reader.readInt()];
            reader.readFully(bytesReceive);
            System.out.println(bytesReceive.length);
            for (int j = 0; j < nrOfNodes; j++) {
                System.out.println(j);
                bytesReceive = CryptoUtil.decryptAES(bytesReceive, bytesReceive.length, secretKeys[j]);
            }
            System.out.println(new String(bytesReceive, StandardCharsets.UTF_8));

        }
        socket.close();
    }

    public void getPublicKey() throws Exception {
        String msg = "GivePK!!!";
        for (int i = 0; i < nrOfNodes; i++) {
            //Public key is first received from using the method askForKey for the first node, then
            //we use connectSetup method to get public keys for the rest of the nodes.
            if (i == 0){
                //public key for first node is received
                publicKeys[0] = askForKey(msg);
                byte[] secretKey = CryptoUtil.encryptRSA(secretKeys[0].getEncoded(), secretKeys[0].getEncoded().length, publicKeys[0]);
                //secret key is encrypted in the public key received and is sent
                writer.writeInt(secretKey.length);
                writer.write(secretKey);
                //confirmation is received from the first node
                byte[] confirmation = new byte[reader.readInt()];
                reader.readFully(confirmation);
                confirmation = CryptoUtil.decryptAES(confirmation, confirmation.length, secretKeys[0]);
                System.out.println(new String(confirmation, StandardCharsets.UTF_8) + " -node " + (i+1));
            }
            else {
                //public key for first node is received
                publicKeys[i] = connectSetup(i, msg);
                System.out.println("public key received from node " + i);
                byte[] secretKey = CryptoUtil.encryptRSA(secretKeys[i].getEncoded(), secretKeys[i].getEncoded().length, publicKeys[i]);
                //secret key encrypted in prev node secret keys and is sent
                secretKey = encrypt(i,secretKey);
                writer.writeInt(secretKey.length);
                writer.write(secretKey);
                System.out.println("secret key sent");
                //confirmation is received from nodes and decrypted
                byte[] confirmation = new byte[reader.readInt()];
                System.out.println("confirmation received from node " + i);
                reader.readFully(confirmation);
                for (int j = 0; j <= i; j++) {
                    System.out.println("node " + (j+1) + " decrypted");
                    confirmation = CryptoUtil.decryptAES(confirmation, confirmation.length, secretKeys[j]);
                }
                System.out.println((new String(confirmation, StandardCharsets.UTF_8)) + " -node " + (i+1));
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
    public PublicKey askForKey(String msg) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

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
    private PublicKey connectSetup(int i, String msg) throws Exception{
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

                System.out.println(inetAddresses[j + 1] + ":" + portsToVisit[j + 1]);

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
            System.out.println(j);
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
    public byte[] encrypt(int nowNode, byte[] msg) throws Exception {
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
            //ip and endport of server is encrypted in the loop
            if (i == nrOfNodes-1) {
                byteBuffer = ByteBuffer.allocate(msgBytes.length
                        + inetAddresses[inetAddresses.length-1].getBytes().length
                        + String.valueOf(portsToVisit[portsToVisit.length-1]).getBytes().length
                );
                byteBuffer.put(msgBytes);
                byteBuffer.flip();
                byteBuffer.get(msgBytes);
                msgBytes = new byte[byteBuffer.limit()];
            }
            msgBytes = CryptoUtil.encryptAES(msgBytes, msgBytes.length, secretKeys[i]);
        }
        return msgBytes;
    }

    public static void main(String[] args) throws Exception {
        int tempNodes = 3;
        OnionClient onionClient = new OnionClient(tempNodes, "localhost", 8119);
        onionClient.setDest();
        onionClient.run();
    }
}
