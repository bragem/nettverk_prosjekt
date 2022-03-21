import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

//TODO JAVADOC OG kommentarer Overalt
public class OnionClient {

    InputStreamReader readerConn;
    BufferedReader reader;
    PrintWriter writer;

    private final int HEADER = 40;
    private int nrOfNodes;
    private int[] portsToVisit;
    private String[] inetAddresses;
    private DatagramSocket socket;
    String endIP;
    int endPort;

    private SecretKey[] secretKeys;
    private PublicKey[] publicKeys;

    public OnionClient(int nrOfNodes, String ip, int endPort) throws SocketException {
        this.socket = new DatagramSocket();
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
        readerConn = new InputStreamReader(socket.getInputStream());
        reader = new BufferedReader(readerConn);
        writer = new PrintWriter(socket.getOutputStream(), true);
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
                byte[] bytesToExit = new byte[0]; //TODO encrypting method
                DatagramPacket dpSend = new DatagramPacket(bytesToExit, bytesToExit.length, InetAddress.getByName(inetAddresses[0]), portsToVisit[0]);//TODO change dynamic user input localhost and ports of all
                socket.send(dpSend);
                System.out.println("Shutdown complete.");
                break;
            }

            //Sending messages packets
            byte[] byteMessage = msg.getBytes(StandardCharsets.UTF_8);


            System.out.println("Message being sent");
            System.out.println("Message being encrypted");

            //TODO ENCRYPT the bytemessage
//            String encryptMessage = encrypt(byteMessage);
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

    private void connectSetup() throws Exception{
        for (int i = 0; i < nrOfNodes; i++) {
            //encrypt secret keys for
            byte[] secretKeyByte = secretKeys[i].getEncoded();
            PublicKey publicKey = publicKeys[i];
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] cryptData = cipher.doFinal(secretKeyByte);

            for (int j = i - 1 ; j >= 0; j++) {
                ByteBuffer bytes = ByteBuffer.allocate(cryptData.length + HEADER);
                bytes.put(Byte.parseByte(inetAddresses[j+1]));
                bytes.put((byte) ':');
                bytes.put((byte) portsToVisit[j+1]);
                bytes.put(cryptData);

                cryptData = new byte[cryptData.length + HEADER];
                bytes.flip();

                bytes.get(cryptData);

                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeys[j]);

                cryptData = cipher.doFinal(cryptData);
            }

            writer.println(Arrays.toString(cryptData));

            reader.readLine();
        }
    }

    public String encrypt(String msg) {
//        byte[] byteMessage = Arrays.copyOf(msg, msg.length);
//        // encryption
//        for (int i = nrOfNodes -1; i >= 0; i--) {
//            ByteBuffer byteBuffer;
//            if(i != nrOfNodes -1){
//                //TODO clean up and update length plus general upgrade
//                byteBuffer = ByteBuffer.allocate(byteMessage.length + HEADER);
//                byteBuffer.put(inetAddresses[i+1].getBytes());
//                byteBuffer.put((byte)':');
//                byteBuffer.putInt(portsToVisit[i+1]);
//                byteBuffer.put(inetAddresses[i].getBytes());
//                byteBuffer.put((byte)':');
//                byteBuffer.putInt(portsToVisit[i]);
//            }
//            else {
//                byteBuffer = ByteBuffer.allocate(byteMessage.length);
//            }
//            byteBuffer.put(byteMessage);
//            byteBuffer.flip();
//
//            byteMessage = new byte[byteBuffer.limit()];
//            byteBuffer.get(byteMessage);
//
//            //byteMessage //TODO Symetric encryption
//        }
//
        return "byteMessage";
    }

    public static void main(String[] args) throws Exception {
        int tempNodes = 0;
        OnionClient onionClient = new OnionClient(tempNodes, "9999", 1234);
        onionClient.setDest();
        onionClient.connectSetup();
        //TODO metode for noekler
        //TODO metode for aa opprette forbindelse
        onionClient.run();
    }
}
