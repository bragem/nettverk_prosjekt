package components;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class OnionServer {
    final int PORT_NUM = 8119;

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
            System.out.println("Message from Client is: " + clientMsg);

            if(!("quit".equals(clientMsg))) {
                System.out.println("Write your message: ");
                String msg = read.readLine();
                msgBytes = msg.getBytes();
                writer.writeInt(msgBytes.length);
                writer.write(msgBytes);
                System.out.println("Message sent to Client: " + msg);
            } else {
                String msgToClient = (clientMsg + " -love from server");
                msgBytes = msgToClient.getBytes();
                writer.writeInt(msgBytes.length);
                writer.write(msgBytes);
                System.out.println("Shutting down...");
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
