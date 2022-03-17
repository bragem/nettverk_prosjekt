import javax.crypto.SecretKey;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

public class OnionNode {

    // Network info of node
    private String hostName;
    private String IPAddress;
    private int port;

    // Public and private RSA keys for initial setup of connection
    private PrivateKey privateKey;
    private PublicKey publicKey;

    // Secret symmetric key
    private SecretKey secretKey;

    public OnionNode(int port) throws UnknownHostException {
        this.hostName = InetAddress.getLocalHost().getHostName();
        this.IPAddress = InetAddress.getByName(InetAddress.getLocalHost().getHostName()).getHostAddress();
        this.port = port;

        System.out.println("Node starting...");
        System.out.println("Node started at " + this.getIPAddress() + " on port " + this.getPort());
    }

    public String getHostName() {
        return hostName;
    }

    public String getIPAddress() {
        return IPAddress;
    }

    public int getPort() {
        return port;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private void setPublicKey(PublicKey key) {
        this.publicKey = key;
    }

    private void setPrivateKey(PrivateKey key) {
        this.privateKey = key;
    }

    private void setSecretKey(SecretKey key) {
        this.secretKey = key;
    }

    public static void main(String[] args) throws UnknownHostException {
        List<String> argsList = Arrays.asList(args);

        if(argsList.contains("-p")) {
            int port = Integer.parseInt(argsList.get(argsList.indexOf("-p") + 1));
            OnionNode node = new OnionNode(port);
        }


    }
}
