package components;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import utils.CryptoUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class OnionServer {
    final int PORT_NUM = 8119;
    private String IPAddress;

    ServerSocket server = new ServerSocket(PORT_NUM);

    // Secret symmetric key
    private SecretKey secretKey;

    private static Logger logger = LoggerFactory.getLogger(OnionClient.class);

    public OnionServer() throws IOException {
        this.IPAddress = InetAddress.getByName(InetAddress.getLocalHost().getHostName()).getHostAddress();

        logger.info("Server starting...");
        logger.info(String.format("Server started at %s:%s", getIPAddress(), getPort()));
    }

    private SecretKey getSecretKey() {
        return secretKey;
    }

    private void setSecretKey(SecretKey sk) {
        this.secretKey = sk;
    }

    public String getIPAddress() {
        return IPAddress;
    }

    public int getPort() {
        return PORT_NUM;
    }


    public void run() throws IOException {
        ServerSocket server = new ServerSocket(PORT_NUM);
        System.out.println("Waiting for connection...");
        Socket conn = server.accept();
        System.out.println("Connection established");

        DataInputStream reader
                = new DataInputStream(new BufferedInputStream(conn.getInputStream()));
        DataOutputStream writer = new DataOutputStream(conn.getOutputStream());
        BufferedReader read = new BufferedReader(new InputStreamReader(System.in));
        while(true) {
            int l = reader.readInt();
            byte[] msgBytes = new byte[l];
            reader.readFully(msgBytes);
            String clientMsg = new String(msgBytes, StandardCharsets.UTF_8);
            logger.info(String.format("Message from Client is: %s", clientMsg));

            if(!("quit".equals(clientMsg))) {
                System.out.println("Write your message: ");
                String msg = read.readLine();
                msgBytes = msg.getBytes();
                writer.writeInt(msgBytes.length);
                writer.write(msgBytes);
                logger.info(String.format("Message sent to Client: %s", msg));
            } else {
                String msgToClient = (clientMsg + " -love from server");
                msgBytes = msgToClient.getBytes();
                writer.writeInt(msgBytes.length);
                writer.write(msgBytes);
                logger.info("Shutting down...");
                break;
            }
        }

        reader.close();
        writer.close();
        conn.close();
        server.close();
    }

    public static void main(String[] args) throws IOException {
        OnionServer server = new OnionServer();
        server.run();
    }
}
