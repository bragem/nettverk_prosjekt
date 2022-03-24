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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import utils.CryptoUtil;

//TODO JAVADOC OG kommentarer Overalt
public class OnionClient {

    DataInputStream reader;
    DataOutputStream writer;

    private final int HEADER = 7;
    private int nrOfNodes;
    private int[] portsToVisit;
    private String[] inetAddresses;
    private Socket socket;
    String endIP;
    int endPort;

    private SecretKey[] secretKeys;
    private PublicKey[] publicKeys;

    public OnionClient(int nrOfNodes, String ip, int endPort) throws SocketException, NoSuchAlgorithmException {
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

    public void setDest() throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader("C:\\Users\\hassa\\NTNU.Data\\2år\\2.sem\\Nettverksprogg\\onionprosjekt\\nettverk_prosjekt\\src\\main\\java\\ipnports.txt"))) {
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
//        inetAddresses[1] = "10.24.52.125";
//        portsToVisit[1] = 1234;
//        System.out.println(inetAddresses[0] + ":" + portsToVisit[0]);
        this.socket = new Socket(inetAddresses[0], portsToVisit[0]);
        reader = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        writer = new DataOutputStream(socket.getOutputStream());
    }

    private void createSymmetricKeys() throws NoSuchAlgorithmException {
        for(int i = 0; i < nrOfNodes; i++) {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            secretKeys[i] = kg.generateKey();
        }
    }

    private void run() throws Exception {
        System.out.println("Receiving public key from node...");
        getPublicKey();
        System.out.println("\nPublic keys received!");
        System.out.println("Private keys sent!");

        System.out.println("\n\nPlease write your message, enter when finished.");
        System.out.println("Enter '0' without the quotes to exit the program");

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
            }

            //Sending messages packets
            byte[] byteMessage = msg.getBytes(StandardCharsets.UTF_8);

            System.out.println("Message being sent");
            System.out.println("Message being encrypted");

            //TODO ENCRYPT the bytemessage
            byte[] encryptMessage = encryptMessage(byteMessage);
            writer.writeInt(encryptMessage.length);
            writer.write(encryptMessage);
            System.out.println("Message sent: " + msg + "\n");

            //Receiving messages branch setup
            System.out.println("Message from server: ");
            byte[] bytesReceive = new byte[reader.readInt()];
            reader.readFully(bytesReceive);
            System.out.println(bytesReceive.length);
            for (int j = 0; j < nrOfNodes; j++) {
                System.out.println(j);
                bytesReceive = CryptoUtil.decryptAES(bytesReceive, bytesReceive.length, secretKeys[j]);
            }
            System.out.println(new String(bytesReceive, StandardCharsets.UTF_8));
            //TODO DECRYPT Message method.

        }
        socket.close();
    }

    public void getPublicKey() throws Exception {
        String msg = "GivePK!!!";
        for (int i = 0; i < nrOfNodes; i++) {
            if (i == 0){
                publicKeys[0] = askForKey(msg);
                byte[] secretKey = CryptoUtil.encryptRSA(secretKeys[0].getEncoded(), secretKeys[0].getEncoded().length, publicKeys[0]);
                writer.writeInt(secretKey.length);
                writer.write(secretKey);
                byte[] confirmation = new byte[reader.readInt()];
                reader.readFully(confirmation);
                confirmation = CryptoUtil.decryptAES(confirmation, confirmation.length, secretKeys[0]);
                System.out.println(new String(confirmation, StandardCharsets.UTF_8) + " -node " + (i));
            }
            else {
                publicKeys[i] = connectSetup(i, msg);
                System.out.println("public key received from node " + i);
                byte[] secretKey = CryptoUtil.encryptRSA(secretKeys[i].getEncoded(), secretKeys[i].getEncoded().length, publicKeys[i]);
                secretKey = encrypt(i,secretKey);
                writer.writeInt(secretKey.length);
                writer.write(secretKey);
                System.out.println("secret key sent");
                byte[] confirmation = new byte[reader.readInt()];
                System.out.println("confirmation received from node " + i);
                reader.readFully(confirmation);
                for (int j = 0; j <= i; j++) {
                    System.out.println("node " + j + " decrypted");
                    confirmation = CryptoUtil.decryptAES(confirmation, confirmation.length, secretKeys[j]);
                }
                System.out.println((new String(confirmation, StandardCharsets.UTF_8)) + " -node " + (i));
            }
        }
    }

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


    public byte[] encrypt(int nowNode, byte[] msg) throws Exception {
        byte[] byteMessage = Arrays.copyOf(msg, msg.length);
        // encryption
        for (int i = nowNode; i >= 0; i--) {
            ByteBuffer buffer;
            if((i != nowNode)){
                //TODO clean up and update length plus general upgrade
                buffer = ByteBuffer.allocate(byteMessage.length);
                buffer.put(byteMessage);
                buffer.flip();

                byteMessage = new byte[buffer.limit()];
                buffer.get(byteMessage);

                byteMessage = CryptoUtil.encryptAES(byteMessage, byteMessage.length, secretKeys[i]);
            }
            else {
//                raw msg for final destination
                buffer = ByteBuffer.allocate(byteMessage.length);

                buffer.put(byteMessage);
                buffer.flip();

                byteMessage = new byte[buffer.limit()];
                buffer.get(byteMessage);

//                byteMessage = CryptoUtil.encryptRSA(byteMessage, byteMessage.length, publicKeys[nowNode]);
            }
        }

        return byteMessage;
    }

    public byte[] encryptMessage(byte[] msg) throws Exception {
        byte[] msgBytes = Arrays.copyOf(msg, msg.length);

        for (int i = nrOfNodes-1; i >= 0; i--) {
            ByteBuffer byteBuffer;
            if (i == nrOfNodes-1) {
                byteBuffer = ByteBuffer.allocate(msgBytes.length
                                + inetAddresses[inetAddresses.length-1].getBytes().length
                                + String.valueOf(portsToVisit[portsToVisit.length-1]).getBytes().length
                        );
                byteBuffer.put(msgBytes);
            } else {
                byteBuffer = ByteBuffer.allocate(msgBytes.length);
                byteBuffer.put(msgBytes);
            }

            byteBuffer.flip();

            msgBytes = new byte[byteBuffer.limit()];
            byteBuffer.get(msgBytes);

            msgBytes = CryptoUtil.encryptAES(msgBytes, msgBytes.length, secretKeys[i]);
        }
        return msgBytes;
    }

    public static void main(String[] args) throws Exception {
        int tempNodes = 3;
        OnionClient onionClient = new OnionClient(tempNodes, "localhost", 8119);
        onionClient.setDest();
//        onionClient.connectSetup();
        //TODO metode for noekler
        //TODO metode for aa opprette forbindelse
        onionClient.run();
//        Socket socket = new Socket("10.22.51.37", 8118);
//        DataOutputStream writer = new DataOutputStream(socket.getOutputStream());
//        DataInputStream reader = new DataInputStream(socket.getInputStream());
//
//        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//        keyGen.init(128);
//        SecretKey sc = keyGen.generateKey();
//
//        String a = "heisann";
//        byte[] ba = a.getBytes();
//        writer.writeInt(ba.length);
//        writer.write(ba);
//
//        byte[] msg = new byte[reader.readInt()];
//        reader.readFully(msg);
//        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(msg));
//
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//
//        System.out.println(sc.toString());
//
//        byte[] encryptedSc = cipher.doFinal(sc.getEncoded(), 0, sc.getEncoded().length);
//        writer.writeInt(encryptedSc.length);
//        writer.write(encryptedSc);
//        System.out.println(Arrays.toString(encryptedSc));
//
//        System.out.println("her");
//        int r = reader.readInt();
//        System.out.println(r);
//        System.out.println("her2");
////        int r =16;
////        System.out.println(r);
//        System.out.println("her3");
//        byte[] msg2 = new byte[r];
//        reader.readFully(msg2);
//        byte[] decrypted = CryptoUtil.decryptAES(msg2,msg2.length,sc);
//        String k = new String(decrypted, StandardCharsets.UTF_8);
//        System.out.println(k);
    }
}
