import java.io.IOException;
import java.net.*;

public class OnionServer {
    DatagramSocket ds = new DatagramSocket(1001);
    byte[] bytArr = new byte[1024];
    DatagramPacket dpReceive = new DatagramPacket(bytArr, bytArr.length);
    DatagramPacket dpSend;
    InetAddress inetAddress = InetAddress.getLocalHost();

    public OnionServer() throws UnknownHostException, SocketException{
    }

    public void start() throws IOException {
        System.out.println("Server booting...");
        String received = "-1";
        while (!received.isBlank()) {

            ds.receive(dpReceive);
            received = (new String(dpReceive.getData(), 0, dpReceive.getLength()));

            System.out.println("Message received: " + received);

            String solved = "Message received: " + received;
            byte[] send = solved.getBytes();

            dpSend = new DatagramPacket(send, send.length, inetAddress, dpReceive.getPort());
            ds.send(dpSend);
        }
    }

    public void close(){
        ds.close();
    }

    public static void main(String[] args) throws IOException {
        OnionServer server = new OnionServer();
        server.start();
        server.close();
    }
}
