/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.ufrgs.rmpestano.rsa;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author Rafael M. Pestano
 */
public interface RSA extends Serializable {

    /**
     * Encrypts a message through <b>C = M^e mod n</b> where: <ul> <li>C =
     * encrypted message <li>M = message to be encrypted <li>e = relative prime
     * to phi <li>n = modulo obtained from p*q </ui>
     *
     * @param message to be encrypted
     * @return encrypted message represented by a Java BigInteger 
     */
    BigInteger encrypt(BigInteger bigInteger);

    /**
     * Encrypts a message using the encrypt method checking if message blocks
     * are valid
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#encrypt(java.math.BigInteger)
     * @param message string
     * @return a list of encrypted message blocks where each encrypted block is represented by a Java BigInteger
     */
    List<BigInteger> encryptMessage(final String message);

    /**
     * Encrypts a message through <b>C = M^e mod n</b> where: <ul> <li>C =
     * encrypted message <li>M = message to be encrypted <li>e = relative prime
     * to phi <li>n = modulo obtained from p*q </ui>
     *
     * @param filePath path to a file containing the message to be encripted
     * @return a BigInteger representing each encrypted file line
     */
    List<BigInteger> encryptFile(String filePath);

    /**
     * decrypt an encrypted message through <b>M = C^d mod n</b> where: <ul>
     * <li>M = decrypted message <li>C = encrypted message <li>d = private key -
     * obtained from multiplicative inverse of 'e' mod 'phi' <li>n = modulo -
     * obtained from p*q </ul>
     *
     * @param encrypted encrypted message
     * @return decrypted message represented by a Java BigInteger type
     */
    BigInteger decrypt(BigInteger encrypted);

    /**
     * decrypt a list of encrypted messages through <b>M = C^d mod n</b> where:
     * <ul> <li>M = decrypted message <li>C = encrypted message <li>d = private
     * key - obtained from multiplicative inverse of 'e' mod 'phi' <li>n =
     * modulo - obtained from p*q </ul>
     *
     * @param encryption encrypted messages represented by a list of Java BigInteger
     * @return list of decrypted message
     */
    List<BigInteger> decrypt(List<BigInteger> encryption);

    /**
     * digitally signs a message through <b>A = M^d mod n</b> where: <ul> <li>A
     * = signed message <li>M = message to be digitally signed <li>d = private
     * key - obtained from multiplicative inverse of 'e' mod 'phi' <li>n =
     * modulo - obtained from p*q </ul>
     *
     * @param message to be digitally signed
     * @return signed message represented by a Java BigInteger
     */
    BigInteger sign(BigInteger bigInteger);

    /**
     * Signs a message using the sign method checking if message blocks are
     * valid
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#sign(java.math.BigInteger)
     * @param message string
     * @return a list of signed message blocks where each signed block is represented by a Java BigInteger
     */
    List<BigInteger> signMessage(final String message);

    /**
     * Signs each line of a file using the sign method
     * @see RSA#signMessage(java.lang.String) 
     * @param filePath
     * @return a BigInteger representing each signed lines
     */
    List<BigInteger> signFile(String filePath);

    /**
     * verifies a signed message through <b>A^e mod n = M</b> where: <ul> <li>A
     * = signed message <li>e = relative prime to phi <li>n = modulo - obtained
     * from p*q <li>M = original message </ul>
     *
     * @param message to be verified
     * @return decimal number result from verification , if its equal to the
     * decimal representation of the original message then its successfully
     * verified
     * @see RSA#isVerified(java.math.BigInteger, java.math.BigInteger)
     *
     */
    BigInteger Verify(BigInteger signedMessage);

    /**
     * verifies a list of signed messages through verify method
     *
     * @param signedMessages
     * @return list of verified messages
     * @see RSA#Verify(java.math.BigInteger)
     */
    List<BigInteger> verify(List<BigInteger> signedMessages);

    /**
     * @param signedMessage
     * @param original message
     * @return <code>true</code> if decimal representation of the original
     * message matched the decimal representation of the signed message
     * <code>false</code> otherwise
     *
     * @see RSA#Verify(java.math.BigInteger)
     */
    boolean isVerified(BigInteger signedMessage, BigInteger message);
    
    /**
     * @param message
     * @return decimal representation of the message
     */
    List<BigInteger> messageToDecimal(final String message);
            
    /**
     * @param filePath
     * @return decimal representation of a file
     */
    List<BigInteger> fileToDecimal(final String filePath);
}
