import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

//TODO JAVADOC OG kommentarer Overalt
public class OnionClient {

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

    public void setDest(){
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
    }

    private void run() throws IOException {
        System.out.println("Please write your message, enter when finished.");
        System.out.println("Enter 'exit' without the quotes to exit the program");
        while (true) {
            System.out.println("Write your message: ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String msg = reader.readLine();

            //Ending connection that is established
            if (msg == null || msg.trim().equalsIgnoreCase("0")){
                System.out.println("Shutting down...");
                byte[] bytesToExit = new byte[0]; //TODO encrypting method
                DatagramPacket dpSend = new DatagramPacket(bytesToExit, bytesToExit.length, InetAddress.getByName(inetAddresses[0]), portsToVisit[0]);//TODO change dynamic user input localhost and ports of all
                socket.send(dpSend);
                System.out.println("Shutdown complete.");
                break;
            }

            //Sending Datagram packets
            byte[] byteMessage = msg.getBytes(StandardCharsets.UTF_8);
            System.out.println("Message being sent");
            //TODO ENCRYPT the bytemessage
            DatagramPacket dpSend = new DatagramPacket(byteMessage, byteMessage.length, InetAddress.getByName(inetAddresses[0]), portsToVisit[0]);
            socket.send(dpSend);
            System.out.println("Message sent: " + msg);

            //Receiving Datagram packets
            System.out.println("Message from server: ");
            byte[] bytesReceive = new byte[1024];
            DatagramPacket dpReceive = new DatagramPacket(bytesReceive, byteMessage.length);
            socket.receive(dpReceive);
            //TODO DECRYPT Message method.
            System.out.println(new String(dpReceive.getData(), 0, dpReceive.getLength()));
        }
        socket.close();
    }

    private void getKeys() throws Exception{

    }

    public byte[] encrypt(byte[] msg) {
        byte[] byteMessage = Arrays.copyOf(msg, msg.length);
        // encryption
        for (int i = nrOfNodes -1; i >= 0; i--) {
            ByteBuffer byteBuffer;
            if(i != nrOfNodes -1){
                //TODO clean up and update length plus general upgrade
                byteBuffer = ByteBuffer.allocate(byteMessage.length + HEADER);
                byteBuffer.put(inetAddresses[i+1].getBytes());
                byteBuffer.put((byte)':');
                byteBuffer.putInt(portsToVisit[i+1]);
                byteBuffer.put(inetAddresses[i].getBytes());
                byteBuffer.put((byte)':');
                byteBuffer.putInt(portsToVisit[i]);
            }
            else {
                byteBuffer = ByteBuffer.allocate(byteMessage.length);
            }
            byteBuffer.put(byteMessage);
            byteBuffer.flip();

            byteMessage = new byte[byteBuffer.limit()];
            byteBuffer.get(byteMessage);

            //byteMessage //TODO Symetric encryption
        }

        return byteMessage;
    }

    public static void main(String[] args) throws IOException {
        int tempNodes = 0;
        OnionClient onionClient = new OnionClient(tempNodes, "9999", 1234);
        onionClient.setDest();
        //TODO metode for noekler
        //TODO metode for aa opprette forbindelse
        onionClient.run();
    }
}
