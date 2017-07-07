/*
    Para que estp funcione es necesario descargar e insatlar el JCE Unlimited
    Strength Jurisdiction Policy Files (archivos de poliza de jurisdicción de
    fuerza de encripción ilimitada), se pueden encontrar para Java 8 aqui:
    http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
    Para instalar se debe entrar al directorio donde se encuentra el JRE y/o el JDK,
    entrar a la carpeta lib correspondiente y reemplazar los .jar correspondientes en
    dichas carpetas.

    Le doy credito a stuinzuri  por el guardado/lectura de llaves,
    fue modificada para funcionar con librerias nativas de Java:
    https://github.com/stuinzuri/SimpleJavaKeyStore
    Y a iterato por el ejemplo AES, fue modificado para que 
    funcionara con una llave generada aleatoriamente:
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
    // Algoritmo de la llave que se generará
    private static final String ALGO = "AES";
    // Tamaño de la llave
    private static final int KEYSZ = 256;// 128 default; 192 y 256 también posibles

    public static void main(String[] args) throws Exception
    {
        // Archivo en donde se guardará la llave
        String file_name = "k.key";
        
        SecretKey sk = generateKey();

        // Guardar y cargar la llave, para demostrar funcionalidad
        saveKey(sk,file_name);
        SecretKey k = loadKey(file_name);
        
        //Texto a encriptar
        String clean = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce at est posuere, facilisis justo id, sollicitudin nunc.";

        // Se convierte la llave a string y se imprime, para demostrar funcionalidad
        String encodedKey = Base64.getEncoder().encodeToString(k.getEncoded());
        System.out.println("Llave = "+encodedKey+"\n");
        System.out.println("Texto a encriptar: "+clean+"\n");

        byte[] encrypted = encrypt(clean, k);
        
        String e = new String(encrypted);
        System.out.println("Texto Encriptado: "+e+"\n");
        
        String decrypted = decrypt(encrypted, k);
        
        System.out.println("Texto decriptado: "+decrypted+"\n");
    }

    public static byte[] encrypt(String plainText, SecretKey key) throws Exception
    {
        byte[] clean = plainText.getBytes();

        // Se genera el valor de inicialización.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Se encripta.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        // Se combina el valor de inicialización y el string encriptado.
        // Es necesario saber el valor de inicialización para decriptar.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        return encryptedIVAndText;
    }

    public static String decrypt(byte[] encryptedIvTextBytes, SecretKey key) throws Exception
    {
        int ivSize = 16;

        // Se extrae el valor de inicalización.
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Se extrae la parte encriptada.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);

        // Se decripta.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);

        return new String(decrypted);
    }

    // Método para generar la llave
    public static SecretKey generateKey() throws NoSuchAlgorithmException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGO);
        keyGenerator.init(KEYSZ); 
        SecretKey key = keyGenerator.generateKey();
        return key;
    }
    
    // Método para guardar la llave
    public static void saveKey(SecretKey key, String file_name) throws IOException
    {
        byte[] encoded = key.getEncoded();
        String data = Base64.getEncoder().encodeToString(encoded);
        File file = new File(file_name);
        PrintWriter out = new PrintWriter(file);
        out.print(data);
        out.close();
    }
    
    // Método para cargar la llave
    public static SecretKey loadKey(String file) throws IOException
    {
        String data = new String(Files.readAllBytes(Paths.get(file)));
        byte[] decodedKey = Base64.getDecoder().decode(data);
        SecretKey key = new SecretKeySpec(decodedKey, ALGO);
        return key;
    }

}