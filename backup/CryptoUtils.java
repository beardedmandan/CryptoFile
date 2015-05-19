/*
 * Maybe you can use this, maybe you cant. The question is would you want to?
 */
package cryptofile;

import static com.sun.org.apache.bcel.internal.util.SecuritySupport.getResourceAsStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Arrays;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * A utility class that encrypts or decrypts a file.
 *
 * @author Dan Harris (harr0710)
 *
 * Includes code modified from sources:
 * @author www.codejava.net
 * (http://www.codejava.net/coding/file-encryption-and-decryption-simple-example)
 * @author www.mykong.com (http://www.mkyong.com/java/java-sha-hashing-example/)
 * @author javamex.com
 * (http://javamex.com/tutorials/cryptography/rsa_encryption.shtml)
 */
public class CryptoUtils {

    private static String ALGORITHM = "AES";

    public static void encrypt(String key, File inputFile, File outputFile, String algorithm)
            throws CryptoException {
        ALGORITHM = algorithm;
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
        System.out.println("Successful Encryption..");
    }

    
    public static void decrypt(String key, File inputFile, File outputFile, String algorithm)
            throws CryptoException {
        ALGORITHM = algorithm;
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
        System.out.println("Successful Decryption..");
    }

    
    public static void hash(File inputFile, File outputFile, String algorithm)
            throws CryptoException {
        try {
            ALGORITHM = algorithm;
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            FileInputStream inputStream = new FileInputStream(inputFile);

            byte[] dataBytes = new byte[1024];

            int nread = 0;
            while ((nread = inputStream.read(dataBytes)) != -1) {
                md.update(dataBytes, 0, nread);
            }

            byte[] mdbytes = md.digest();

            StringBuilder sb = new StringBuilder();
            sb.append(ALGORITHM + ": ");
            for (int i = 0; i < mdbytes.length; i++) {
                sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            byte[] outputHash = sb.toString().getBytes("UTF-8");

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputHash);

            inputStream.close();
            outputStream.close();

            System.out.println("Successful Hash Generation..");

        } catch (IOException | NoSuchAlgorithmException ex) {
            throw new CryptoException("Error hashing file", ex);
        }
    }

    
    private static void doCrypto(int cipherMode, String key, File inputFile,
            File outputFile) throws CryptoException {
        try {
            byte[] keyByte = key.getBytes("UTF-8"); //get bytes of key in UTF-8
            // MessageDigest sha = MessageDigest.getInstance("SHA-1");
            // keyByte = sha.digest(keyByte); //use SHA-1 to transform key-bytes
            keyByte = Arrays.copyOf(keyByte, 16); // use only first 128 bit

            Key secretKey = new SecretKeySpec(keyByte, ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM); //transformation
            cipher.init(cipherMode, secretKey);

            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    
    public static void generateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();

        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

        saveToFile("public.key", pub.getModulus(), pub.getPublicExponent());
        saveToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
        System.out.println("Successful Private/Public Key generation..");
    }

    
    public static void doCryptoRSA(char mode, File inputFile, File outputFile) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            
            if(mode == 'd'){ //decrypt mode
                PrivateKey privKey = readPrivKeyFromFile("private.key");
                cipher.init(Cipher.DECRYPT_MODE, privKey);
                System.out.println("Successful Decryption..");
            } else { //encrypt mode
                PublicKey pubKey = readPubKeyFromFile("public.key");                
                cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                System.out.println("Successful Encryption..");
            }
            
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
            
            byte[] outputBytes = cipher.doFinal(inputBytes);
            
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
            
            inputStream.close();
            outputStream.close();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    
    private static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }

    
    private static PublicKey readPubKeyFromFile(String keyFileName) throws CryptoException, IOException {
        InputStream in = new FileInputStream(keyFileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        } finally {
            oin.close();
        }
    }
    
    
     private static PrivateKey readPrivKeyFromFile(String keyFileName) throws CryptoException, IOException {
        InputStream in = new FileInputStream(keyFileName);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privKey = fact.generatePrivate(keySpec);
            return privKey;
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        } finally {
            oin.close();
        }
    }
}
