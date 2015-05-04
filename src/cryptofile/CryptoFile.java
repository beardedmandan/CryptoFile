/*
 * Maybe you can use this, maybe you cant. The question is would you want to?
 */
package cryptofile;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Dan Harris (harr0710)
 * Based on work from tutorial at:
 * http://www.mkyong.com/java/jce-encryption-data-encryption-standard-des-tutorial/
 */
public class CryptoFile {

    /**
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        String key = "Mary has one cat1";
        File inputFile = new File("document.txt");
        File encryptedFile = new File("document.encrypted");
        File decryptedFile = new File("document.decrypted");
         
        try {
           // CryptoUtils.encrypt(key, inputFile, encryptedFile);
            CryptoUtils.decrypt(key, encryptedFile, decryptedFile);
        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

    }

}
