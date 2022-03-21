import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import utils.CryptoUtil;

//TODO JAVADOC OG kommentarer Overalt
public class OnionClient {

    DataInputStream reader;
    DataOutputStream writer;

    private final int HEADER = 34;
    private int nrOfNodes;
    private int[] portsToVisit;
    private String[] inetAddresses;
    private Socket socket;
    String endIP;
    int endPort;

    private SecretKey[] secretKeys;
    private PublicKey[] publicKeys;

    public OnionClient(int nrOfNodes, String ip, int endPort) throws SocketException {
        this.socket = new Socket();
        this.endIP = ip;
        this.endPort = endPort;
        this.nrOfNodes = nrOfNodes;
        this.secretKeys = new SecretKey[nrOfNodes];
        this.publicKeys = new PublicKey[nrOfNodes];
        this.portsToVisit = new int[nrOfNodes+1];
        this.inetAddresses = new String[nrOfNodes+1];
    }

    public void setDest() throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader("ipnports.txt"))) {
            String line = br.readLine();
            int i = 0;
            while (line != null) {
                String[] split = line.split(":");
                inetAddresses[i] = split[0];
                portsToVisit[i] = Integer.parseInt(split[1]);
                line = br.readLine();
                i++;
            }
            inetAddresses[i] = endIP;
            portsToVisit[i] = endPort;
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.socket = new Socket(inetAddresses[0], portsToVisit[0]);
        reader = new DataInputStream(socket.getInputStream());
        writer = new DataOutputStream(socket.getOutputStream());
    }

    private void createSymmetricKeys(int numberOfKeys) throws NoSuchAlgorithmException, NoSuchAlgorithmException {
        for(int i = 0; i < numberOfKeys; i++) {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(i);
            SecretKey sk = kg.generateKey();
        }
    }

    private void run() throws IOException {
        System.out.println("Please write your message, enter when finished.");
        System.out.println("Enter 'exit' without the quotes to exit the program");


        while (true) {
            System.out.println("Write your message: ");
            BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
            String msg = read.readLine();

            //Ending connection that is established
            if (msg == null || msg.trim().equalsIgnoreCase("0")){
                System.out.println("Shutting down...");
//                String exitString = teardownConnection();
//                writer.println(exitString);


                System.out.println("Shutdown complete.");
                break;

                // DatagramPacket dpSend = new DatagramPacket(bytesToExit, bytesToExit.length, InetAddress.getByName(inetAddresses[0]), portsToVisit[0]);//TODO change dynamic user input localhost and ports of all
            }

            //Sending messages packets
            byte[] byteMessage = msg.getBytes(StandardCharsets.UTF_8);


            System.out.println("Message being sent");
            System.out.println("Message being encrypted");

            //TODO ENCRYPT the bytemessage
//            byte[] encryptMessage = encrypt(byteMessage);
//            writer.println(encryptedMessage);
            System.out.println("Message sent: " + msg);

            //Receiving Datagram packets
            System.out.println("Message from server: ");
            byte[] bytesReceive = new byte[1024];
//            socket.receive(dpReceive);
            //TODO DECRYPT Message method.
//            System.out.println(new String(dpReceive.getData(), 0, dpReceive.getLength()));
        }
        socket.close();
    }

    public void getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        for (int i = 0; i < nrOfNodes; i++) {
            if (i == 0){
                publicKeys[0] = askForKey();
                SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
                secretKeys[0] = secretKey;
            }
//            connectSetup();
        }
    }

    public PublicKey askForKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String askForKey = "Give me your public key";

        byte[] askForKeyBytes = askForKey.getBytes();
        writer.writeInt(askForKeyBytes.length);
        writer.write(askForKeyBytes);

        int l = reader.readInt();
        byte[] decrypted = new byte[l];
        reader.readFully(decrypted);

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decrypted);
        return KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    }

    private void connectSetup(int nrOfEncryptions, String msg) throws Exception{
        for (int i = 0; i < nrOfNodes; i++) {
            //encrypt secret keys for
            byte[] secretKeyByte = secretKeys[i].getEncoded();
            PublicKey publicKey = publicKeys[i];
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] cryptData = cipher.doFinal(secretKeyByte);

            for (int j = i - 1 ; j >= 0; j++) {
                ByteBuffer buffer = ByteBuffer.allocate(cryptData.length + HEADER);
                buffer.put(Byte.parseByte(inetAddresses[j+1]));
                buffer.put((byte) ':');
                buffer.put((byte) portsToVisit[j+1]);
                buffer.put(cryptData);

                cryptData = new byte[cryptData.length + HEADER];
                buffer.flip();

                buffer.get(cryptData);

                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeys[j]);

                cryptData = cipher.doFinal(cryptData);
            }

            writer.writeInt(cryptData.length);
            writer.write(cryptData);

            int l = reader.readInt();
            byte[] decrypted = new byte[l];
            reader.readFully(decrypted);

            for (int j = 0; j <= i; j++) {
                decrypted = CryptoUtil.decrypt(decrypted, l, secretKeys[j]);
                if (j==i){//TODO sett en skikkelig sjekk her
                    System.out.println("Received ack from node " + portsToVisit[i]);
                }
            }
        }
    }

    public byte[] encrypt(byte[] msg) {
        byte[] byteMessage = Arrays.copyOf(msg, msg.length);
        // encryption
        for (int i = nrOfNodes -1; i >= 0; i--) {
            ByteBuffer buffer;
            if(i != nrOfNodes -1){
                //TODO clean up and update length plus general upgrade
                buffer = ByteBuffer.allocate(byteMessage.length + HEADER);
                buffer.put(inetAddresses[i+1].getBytes());
                buffer.put((byte)':');
                buffer.putInt(portsToVisit[i+1]);
            }
            else {
                //raw msg for final destination
                buffer = ByteBuffer.allocate(byteMessage.length);
            }
            buffer.put(byteMessage);
            buffer.flip();

            byteMessage = new byte[buffer.limit()];
            buffer.get(byteMessage);

//            byteMessage =

        }

        return byteMessage;
    }

    public static void main(String[] args) throws Exception {
        int tempNodes = 0;
        OnionClient onionClient = new OnionClient(tempNodes, "9999", 1234);
        onionClient.setDest();
//        onionClient.connectSetup();
        //TODO metode for noekler
        //TODO metode for aa opprette forbindelse
        onionClient.run();
    }
}
