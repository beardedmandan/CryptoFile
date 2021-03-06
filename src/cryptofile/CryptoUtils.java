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
import java.nio.ByteBuffer;
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
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
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
 * @author http://coding.westreicher.org/?p=23
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

    
    public static void doCryptoRSA(char mode, String algorithm, File inputFile, File outputFile) throws CryptoException, ShortBufferException {
        try {
            //intialise variables
            ALGORITHM = algorithm;
            Cipher cipher;
            byte[] inputBytes = new byte[(int) inputFile.length()];
            byte[] output = new byte[0];
            
            //prepare input for encryption/decryption in byte format
            FileInputStream inputStream = new FileInputStream(inputFile);
            inputStream.read(inputBytes);
            
            if(mode == 'd'){ //decrypt mode
                //load previously generated key
                PrivateKey privKey;
                privKey = readRSAPrivKeyFromFile("private.key"); //RSA encryption
                cipher = Cipher.getInstance(ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, privKey);
                
                output = blockCipher(inputBytes, Cipher.DECRYPT_MODE, cipher);
                System.out.println("Successful Decryption..");   
                
            } else { //encrypt mode
                //load previously generated key
                PublicKey pubKey;   
                pubKey = readRSAPubKeyFromFile("public.key"); //RSA encryption
                cipher = Cipher.getInstance(ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                             
                output = blockCipher(inputBytes, Cipher.ENCRYPT_MODE, cipher);
                System.out.println("Successful Encryption..");
            }
            
            //write output
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(output);
            
            inputStream.close();
            outputStream.close();
            
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file", ex);
        }
    }

    
    public static void generateKey(String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        ALGORITHM = algorithm;
        
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(1024); //1024 bit key length
        KeyPair kp = kpg.genKeyPair();
        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();

        KeyFactory fact = KeyFactory.getInstance(ALGORITHM);
        
        RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
        saveRSAKeyToFile("public.key", pub.getModulus(), pub.getPublicExponent());
        saveRSAKeyToFile("private.key", priv.getModulus(), priv.getPrivateExponent());
        
        System.out.println("Successful Private/Public Key generation..");
    }
            
    
    private static void saveRSAKeyToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
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
 
    
    private static PublicKey readRSAPubKeyFromFile(String keyFileName) throws CryptoException, IOException {
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
    
    
     private static PrivateKey readRSAPrivKeyFromFile(String keyFileName) throws CryptoException, IOException {
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
     
     
    private static byte[] blockCipher(byte[] bytes, int cipherMode, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException{
	// initialize 2 buffers.	
	byte[] scrambled = new byte[0];	// scrambled will hold intermediate results
	byte[] toReturn = new byte[0]; // toReturn will hold the total result
        
	// if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
        // key is set at 1024 for RSA
	int length = (cipherMode == Cipher.ENCRYPT_MODE)? 100 : 128;

	byte[] buffer = new byte[length];

	for (int i=0; i< bytes.length; i++){           
		// if we filled our buffer array we have our block ready for de- or encryption
		if ((i > 0) && (i % length == 0)){              
			scrambled = cipher.doFinal(buffer);
			toReturn = append(toReturn,scrambled); // add the result to our total result.
			int newlength = length; // calculate length of next buffer required

			// if newlength is longer than remaining bytes in the bytes array it is shortened.
			if (i + length > bytes.length) {
				 newlength = bytes.length - i;
			}		
			buffer = new byte[newlength]; // clean buffer array
		}		
		buffer[i%length] = bytes[i]; // copy byte into our buffer.
	}

	// this step is needed if a trailing buffer is found when encrypting.
	scrambled = cipher.doFinal(buffer);
	toReturn = append(toReturn,scrambled);

	return toReturn;
    }
    
    
    private static byte[] append(byte[] prefix, byte[] suffix){
	byte[] toReturn = new byte[prefix.length + suffix.length];
        System.arraycopy(prefix, 0, toReturn, 0, prefix.length);
        System.arraycopy(suffix, 0, toReturn, prefix.length, suffix.length);
	return toReturn;
    }
}
