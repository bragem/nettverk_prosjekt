import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.*;

public class OnionServer {
    final int PORT_NUM = 1250;

    public void run() throws IOException {
        ServerSocket server = new ServerSocket(PORT_NUM);
        System.out.println("Waiting for connection...");
        Socket conn = server.accept();
        System.out.println("Connection established");

        InputStreamReader readerConnection
                = new InputStreamReader(conn.getInputStream());
        BufferedReader reader = new BufferedReader(readerConnection);
        PrintWriter writer = new PrintWriter(conn.getOutputStream(), true);

        while(true) {
            String clientMsg = reader.readLine();
            writer.println(clientMsg);

            if(reader.readLine().equals("0")) {
                System.out.println("Shutting down...");
                break;
            } else {
                continue;
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
