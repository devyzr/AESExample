/*
    For this to work we need to download and install the JCE Unlimited
    Strength Jurisdiction Policy Files, you can find them for Java 8 here:
    http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
    Follow the instructions in the zip to install.

    Credit to stuinzuri for the key save/retrieve, it was modded to work with Java libs:
    https://github.com/stuinzuri/SimpleJavaKeyStore
    and to iterato for the AES example, it was modded to work with a randomly generated key:
    https://gist.github.com/itarato/abef95871756970a9dad
*/

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.io.File;
import java.io.PrintWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;


public class AESExample
{
    private static final String ALGO = "AES";
    private static final int KEYSZ = 256;// 128 default; 192 and 256 also possible

    public static void main(String[] args) throws Exception
    {
        // Key file store
        String file_name = "k.key";
        
        SecretKey sk = generateKey();

        // Save and load key, to demonstrate functionality
        saveKey(sk,file_name);
        SecretKey k = loadKey(file_name);
        
        String clean = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce at est posuere, facilisis justo id, sollicitudin nunc.";

        // Convert key to string, for demonstration purposes
        String encodedKey = Base64.getEncoder().encodeToString(k.getEncoded());
        System.out.println("Key = "+encodedKey+"\n");
        System.out.println("Text to Encrypt: "+clean+"\n");

        byte[] encrypted = encrypt(clean, k);
        
        String e = new String(encrypted);
        System.out.println("Encrypted Text: "+e+"\n");
        
        String decrypted = decrypt(encrypted, k);
        
        System.out.println("Decrypted text: "+decrypted+"\n");
    }

    public static byte[] encrypt(String plainText, SecretKey key) throws Exception
    {
        byte[] clean = plainText.getBytes();

        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        return encryptedIVAndText;
    }

    public static String decrypt(byte[] encryptedIvTextBytes, SecretKey key) throws Exception
    {
        int ivSize = 16;

        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGO);
        keyGenerator.init(KEYSZ); 
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    
    public static void saveKey(SecretKey key, String file_name) throws IOException
    {
        byte[] encoded = key.getEncoded();
        String data = Base64.getEncoder().encodeToString(encoded);
        File file = new File(file_name);
        PrintWriter out = new PrintWriter(file);
        out.print(data);
        out.close();
    }
    
    public static SecretKey loadKey(String file) throws IOException
    {
        String data = new String(Files.readAllBytes(Paths.get(file)));
        byte[] decodedKey = Base64.getDecoder().decode(data);
        SecretKey key = new SecretKeySpec(decodedKey, ALGO);
        return key;
    }
    
}