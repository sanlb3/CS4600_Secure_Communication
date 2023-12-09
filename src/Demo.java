import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Demo {

    static byte[] cipherText;
    static byte[] encryptAESKey;
    static byte[] decryptAESKey;
    static byte[] receiverPubKeyByte;
    static byte[] messageData;
    static byte[] mac;
    static byte[] MAC;
    static byte[] transmittedData;
    static long transmittedDataSize;
    static byte[] encryptedAESKey;
    static byte[] ciphertext;
    static byte[] MACInput;
    static byte[] receiverMac;
    static byte[] macKeyByte;
    static byte[] receiverPrvKeyByte;

    static SecretKey aesKey;
    static SecretKey macKEY;
    static SecretKey AESKey;
    static PublicKey receiverPublicKey;
    static PrivateKey receiverPrivateKey;
    static Key macKey;

    static Path transmittedDataPath;

    static String macKeyFile;
    static String decryptedMessage;
    static String messageFile;
    static String senderMessage;
    static String receiverPubKeyFile;
    static String receiverPubKey;
    static String macKeyString;
    static String receiverPrvKeyFile;
    static String receiverPrvKeyString;

    static Boolean authenticateMac;



    public static void main(String[] args) throws Exception {

        //Step 1 -- Generate RSA Key Pair for Sender and Receiver.
        Sender sender = new Sender();
        sender.generateRSAKeyPair();
        System.out.println("Sender RSA KeyPairs are Generated.");

        Receiver receiver = new Receiver();
        receiver.generateRSAKeyPair();
        System.out.println("Receiver's RSA KeyPairs are Generated.");

        //Step 2 -- Encrypt Sender Message with AES ECB
        messageFile = "src/Sender/message.txt";
        senderMessage = readFile(messageFile);
        aesKey = sender.generateAESKey(256);
        cipherText = sender.encryptAES(senderMessage, aesKey);
        System.out.println("Sender's message is encrypted.");

        //Step 3 -- Read receiver's public key and encrypt AES key using the receiver's public key
        receiverPubKeyFile = "src/Receiver/publicKey.txt";
        receiverPubKey = readFile(receiverPubKeyFile);
        receiverPubKeyByte = Base64.getDecoder().decode(receiverPubKey);
        receiverPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(receiverPubKeyByte));
        encryptAESKey = sender.encryptRSA(aesKey.getEncoded(),receiverPublicKey);
        System.out.println("AES Key is encrypted using the receiver's public RSA Key.");

        //Step 4 -- Generate MacKey and Mac
        macKey = generateMACKey();
        writeToFile("macKey.txt", Base64.getEncoder().encodeToString(macKey.getEncoded()));
        macKeyFile = "macKey.txt";
        macKeyString = readFile(macKeyFile);
        macKeyByte = (Base64.getDecoder().decode(readFile(macKeyFile)));
        macKEY = new SecretKeySpec(macKeyByte,0,macKeyByte.length,"HmacSHA256");
        messageData = joinByteArray(encryptAESKey, cipherText);
        mac = sender.generateMAC(messageData, macKey);
        System.out.println("Sender Mac is generated");


        //Appends encryptAESCipher, cipherText, and mac and write them into Transmitted_Data file
        messageData = joinByteArray(mac, messageData);
        writeBytes("Transmitted_Data.txt", messageData);
        System.out.println("All Data are written into Transmitted_Data.txt file");

        //Step 5 Receiver successfully authenticate, decrypt message and read the original message
        transmittedDataPath = Paths.get("Transmitted_Data.txt");
        transmittedDataSize = Files.size(transmittedDataPath);
        transmittedData = readBytes("Transmitted_Data.txt");

        //Separate the joined data
        MAC = Arrays.copyOfRange(transmittedData, 0, 32);
        encryptedAESKey = Arrays.copyOfRange(transmittedData, 32, 288);
        ciphertext = Arrays.copyOfRange(transmittedData, 288, (int)(transmittedDataSize));

        //Appends encryptAESKey and ciphertext in order to generate receiverMac
        MACInput = joinByteArray(encryptedAESKey, ciphertext);
        macKey = new SecretKeySpec(macKeyByte,0,macKeyByte.length,"HmacSHA256");
        receiverMac = receiver.generateMAC(MACInput, macKey);

        //Authenticate MAC
        authenticateMac = Arrays.equals(mac, receiverMac);

        if (!authenticateMac)
        {
            throw new Exception("MAC is not authentic");
        } else
        {
            System.out.println("MAC is authentic");
        }

        //Uses receiver's private RSA key to decrypt the message
        receiverPrvKeyFile = "src/Receiver/privateKey.txt";
        receiverPrvKeyString = readFile(receiverPrvKeyFile);
        receiverPrvKeyByte = Base64.getDecoder().decode(receiverPrvKeyString);
        receiverPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(receiverPrvKeyByte));
        decryptAESKey = receiver.decryptRSA(encryptAESKey, receiverPrivateKey);
        AESKey = new SecretKeySpec(decryptAESKey, 0, decryptAESKey.length, "AES");
        System.out.println("AES Key is decrypted using the receiver's private RSA Key.");

        //Decrypts message and writes them into another file to compare with original message
        decryptedMessage = receiver.decryptAES(ciphertext, AESKey);
        writeToFile("decryptedMessage.txt", decryptedMessage);

        System.out.println("\nDecrypted Message: " + decryptedMessage);
    }

    public static Key generateMACKey() throws NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(secureRandom);
        return keyGenerator.generateKey();
    }

    public static void writeToFile(String filename, String data) throws IOException {

        FileWriter writer = new FileWriter(filename);
        writer.write(data);
        writer.close();
    }

    public static void writeBytes(String filename, byte[] data) throws IOException {

        File file = new File(filename);
        FileOutputStream writer = new FileOutputStream(file);
        writer.write(data);
        writer.close();
    }

    public static byte[] readBytes(String filename) throws IOException {

        Path path = Paths.get(filename);
        byte[] data = Files.readAllBytes(path);
        return data;
    }

    public static String readFile(String filename) throws FileNotFoundException {

        File file = new File(filename);
        Scanner reader = new Scanner(file);

        reader.useDelimiter("\\Z");

        String data = reader.next();
        reader.close();

        return data;
    }

    public static byte[] joinByteArray(byte[] byte1, byte[] byte2) throws IOException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.write(byte1);
        outputStream.write(byte2);

        return outputStream.toByteArray();
    }

}
