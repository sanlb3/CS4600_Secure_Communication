import javax.crypto.*;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class Sender {

    public static void generateRSAKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey prvKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        String prvString = Base64.getEncoder().encodeToString(prvKey.getEncoded());
        String pubString = Base64.getEncoder().encodeToString(pubKey.getEncoded());

        writeToFile("src/Sender/privateKey.txt", prvString);
        writeToFile("src/Sender/publicKey.txt", pubString);
    }

    public static SecretKey generateAESKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    public static byte[] encryptRSA(byte[] message, PublicKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] ciphertext = cipher.doFinal(message);
        return ciphertext;
    }

    public static byte[] generateMAC(byte[] message, Key key) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] macResult = mac.doFinal(message);

        return macResult;
    }

    public static byte[] encryptAES(String message, SecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] input = message.getBytes("UTF-8");
        byte[] ciphertext = cipher.doFinal(input);

        return ciphertext;
    }

    public static void writeToFile(String filename, String data) throws IOException {
        FileWriter writer = new FileWriter(filename);
        writer.write(data);
        writer.close();
    }

}
