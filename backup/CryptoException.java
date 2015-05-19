/*
 * Maybe you can use this, maybe you cant. The question is would you want to?
 */

package cryptofile;

/**
 * Handles Crypto exceptions
 * @author Dan Harris (harr0710)
 * 
 * Code modified from sources:
 * @author www.codejava.net (http://www.codejava.net/coding/file-encryption-and-decryption-simple-example)
 */
public class CryptoException extends Exception {
 
    public CryptoException() {
    }
 
    public CryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
