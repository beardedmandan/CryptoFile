/*
 * Maybe you can use this, maybe you cant. The question is would you want to?
 */

package cryptofile;

/**
 * Handles Crypto exceptions
 * @author www.codejava.net
 *
 */
public class CryptoException extends Exception {
 
    public CryptoException() {
    }
 
    public CryptoException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
