import javax.crypto.*;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class Receiver {

    public static void generateRSAKeyPair() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey prvKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        String prvString = Base64.getEncoder().encodeToString(prvKey.getEncoded());
        String pubString = Base64.getEncoder().encodeToString(pubKey.getEncoded());


        writeToFile("src/Receiver/privateKey.txt", prvString);
        writeToFile("src/Receiver/publicKey.txt", pubString);
    }

    public static String decryptAES(byte[] ciphertext, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, "UTF-8");
    }

    public static byte[] decryptRSA(byte[] message, PrivateKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] plaintext = cipher.doFinal(message);
        return plaintext;
    }

    public static byte[] generateMAC(byte[] message, Key key) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] macResult = mac.doFinal(message);

        return macResult;
    }

    public static void writeToFile(String filename, String data) throws IOException {
        FileWriter writer = new FileWriter(filename);
        writer.write(data);
        writer.close();
    }
}
