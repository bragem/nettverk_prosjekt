import utils.CryptoUtil;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class OnionNode {

    // Network info of node
    private String hostName;
    private String IPAddress;
    private int port;

    // Secret symmetric key
    private SecretKey secretKey;

    private ServerSocket serverSocket;
    private Socket socket;

    private String prevIP;
    private int prevPort;

    private String nextIP;
    private int nextPort;

    private Pattern IPv4 = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");

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

    private void setSecretKey(SecretKey key) {
        this.secretKey = key;
    }

    private SecretKey getSecretKey() {
        return this.secretKey;
    }

    /**
     * Sets up a connection between itself and a client or another node
     *
     * @throws Exception
     */
    public void setupConnection() throws Exception {
        serverSocket = new ServerSocket(port);

        Socket connection = serverSocket.accept();
        prevIP = connection.getRemoteSocketAddress().toString().split("[/:]")[1];
        prevPort = connection.getPort();

        System.out.println("IP of connected client: " + prevIP + "\n");
        DataInputStream dis = new DataInputStream(new BufferedInputStream(connection.getInputStream()));

        int byteLength;
        byte[] bytes;
        String received;

        boolean setupComplete = false;

        while(!setupComplete) {
            byteLength = dis.readInt();
            bytes = new byte[byteLength];
            dis.readFully(bytes);

            String tmp = new String(bytes, StandardCharsets.UTF_8);
            System.out.println("Data received: " + tmp + "\n");

            DataOutputStream dos = new DataOutputStream(connection.getOutputStream());


            if("GivePK!!!".equals(tmp)) {
                System.out.println("Received from client: " + tmp + "");
                System.out.println("Sending public key back to client...");

                PublicKey pk = loadRSAPublicKey();


                byte[] stBytes = pk.getEncoded();

                dos.writeInt(stBytes.length);
                dos.write(stBytes);
                System.out.println("Public key was sent\n");
                dos.flush();

            } else if(getSecretKey() == null) { // IPv4.matcher(tmp.substring(0, 11)).matches()
                byte[] decrypted = CryptoUtil.decryptRSA(bytes, bytes.length, loadRSAPrivateKey());

                SecretKey sk = new SecretKeySpec(decrypted, "AES");
                setSecretKey(sk);

                System.out.println("New message received from client: " + new String(sk.getEncoded(), StandardCharsets.UTF_8));

                String response = "My secret key is now set!";
                byte[] responseBytes = response.getBytes();
                byte[] encrypted = CryptoUtil.encryptAES(responseBytes, responseBytes.length, getSecretKey());

                dos.writeInt(encrypted.length);
                dos.write(encrypted);
                dos.flush();
            } else {
                byte[] decrypted = CryptoUtil.decryptAES(bytes, bytes.length, getSecretKey());

                String st = new String(decrypted, StandardCharsets.UTF_8);

                nextIP = st.split("[:/]")[0];
                nextPort = Integer.parseInt(st.split("[:/]")[1]);
                String message = st.split("[:/]")[2];


                System.out.println("Next IP is: " + nextIP + "");
                System.out.println("Next Port is: " + nextPort + "\n");

                System.out.println("Message received from client: " + st);

                forwardData(connection, message);
                setupComplete = true;
            }
        }


    }


    public void forwardData(Socket connection, String firstMessage) throws Exception {
        System.out.println("Message to next node is: " + firstMessage);

        boolean quit = false;
        DataInputStream readFromPrev = new DataInputStream(new BufferedInputStream(connection.getInputStream()));
        DataOutputStream writeToPrev = new DataOutputStream((connection.getOutputStream()));

        socket = new Socket(nextIP, nextPort);
        DataInputStream readFromNext = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        DataOutputStream writeToNext = new DataOutputStream((socket.getOutputStream()));


        writeToNext.writeInt(firstMessage.getBytes().length);
        System.out.println("Length of firstMessage: " + firstMessage.getBytes().length);

        writeToNext.write(firstMessage.getBytes());
        System.out.println("First message to next node is now sent!");

        writeToNext.flush();

        String lastAction = "writeToNext";

        int byteLength = 0;
        byte[] bytes = null;
        byte[] encrypted = null;
        byte[] decrypted = null;


        while(!quit) {

            switch(lastAction){
                case "writeToNext":
                    //trenger sjekk om det står quit eller teardown i meldinga
                    lastAction = "readFromNext";

                    byteLength = readFromNext.readInt();
                    bytes = new byte[byteLength];
                    readFromNext.readFully(bytes);

                    System.out.println("Received message from next node \n");

                    break;
                case "readFromNext":
                    lastAction = "writeToPrev";

                    encrypted = CryptoUtil.encryptAES(bytes, bytes.length, getSecretKey());
                    System.out.println("Message to previous node encrypted!");
                    writeToPrev.writeInt(encrypted.length);
                    writeToPrev.write(encrypted);
                    System.out.println("Message to previous node sent!");

                    break;
                case "writeToPrev":
                    lastAction = "readFromPrev";

                    byteLength = readFromPrev.readInt();
                    bytes = new byte[byteLength];
                    readFromPrev.readFully(bytes);

                    System.out.println("Received message from previous node \n");

                    break;
                case "readFromPrev":
                    lastAction = "writeToNext";

                    decrypted = CryptoUtil.decryptAES(bytes, bytes.length, getSecretKey());
                    System.out.println("Message to next node decrypted!");
                    writeToNext.writeInt(decrypted.length);
                    writeToNext.write(decrypted);
                    System.out.println("Message to next node sent!");

                    break;
                default:
                    System.out.println("wtf?");
            }


//            quit = true;
        }

    }


    /**
     * Creates a new private-public keypair of type RSA
     *
     * @throws NoSuchAlgorithmException if the generator doesn't recognize the encryption algorithm
     * @throws IOException if the saveRSA method fails to save the keys
     */
    private void createRSA() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        PublicKey pub = kp.getPublic();
        PrivateKey pvt = kp.getPrivate();
        saveRSA(pub, pvt);
        //cleanUp(new File("./keys"));
    }

    /**
     * Saves a public and a private key to two different files
     *
     * @param pub the public key
     * @param pvt the private key
     * @throws IOException if it fails to save to file
     */
    private void saveRSA(PublicKey pub, PrivateKey pvt) throws IOException {
        String pubOutFile = "rsa_pub.pub";
        String pvtOutFile = "rsa_pvt.key";

        File dir = new File("./src/main/java/keys/");
        boolean dirCreated = dir.mkdir();

        if(dirCreated) {
            System.out.println("Directory created");

            File rsaPub = new File("./src/main/java/keys/" + pubOutFile);
            File rsaPvt = new File("./src/main/java/keys/" + pvtOutFile);

            try(FileOutputStream fosPub = new FileOutputStream(rsaPub)) {
                fosPub.write(pub.getEncoded());
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }

            try(FileOutputStream fosPvt = new FileOutputStream(rsaPvt)) {
                fosPvt.write(pvt.getEncoded());
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }
        }
    }

    private PrivateKey loadRSAPrivateKey() {

        try {
            Path path = Paths.get("./src/main/java/keys/rsa_pvt.key");
            byte[] bytes = Files.readAllBytes(path);

            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pvt = kf.generatePrivate(ks);

            return pvt;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e);
        }

        return null;
    }

    private PublicKey loadRSAPublicKey() {

        try {
            Path path = Paths.get("./src/main/java/keys/rsa_pub.pub");
            byte[] bytes = Files.readAllBytes(path);

            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(ks);

            return pub;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(e);
        }

        return null;
    }

    private void cleanUp(File file) {
        File[] contents = file.listFiles();
        if (contents != null) {
            for (File f : contents) {
                if (!Files.isSymbolicLink(f.toPath())) {
                    cleanUp(f);
                }
            }
        }
        file.delete();
    }

    public static void main(String[] args) throws Exception {
        List<String> argsList = Arrays.asList(args);

        if(argsList.contains("-p")) {
            int port = Integer.parseInt(argsList.get(argsList.indexOf("-p") + 1));
            OnionNode node = new OnionNode(port);
            node.createRSA();
            node.setupConnection();
            node.cleanUp(new File("./src/main/java/keys"));



            /*System.out.println("Public key format: \n" + node.getPublicKey() + "\n\n");
            System.out.println("Private key format: \n" + node.getPrivateKey() + "\n\n");*/
        }

    }
}
