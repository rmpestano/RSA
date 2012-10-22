/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.ufrgs.rmpestano.rsa;

import java.io.Serializable;
import java.math.BigInteger;

/**
 *
 * @author Rafael M. Pestano
 */
public interface RSA extends Serializable{
    
     /**
     * Encrypts a message through
     * <b>C = M^e mod n</b> where:
     *<ul>
     * <li>C = encrypted message
     * <li>M = message to be encrypted
     * <li>e = relative prime to phi
     * <li>n = modulo obtained from p*q
     *</ui>
     * @param message to be encrypted
     * @return encrypted message
     */
    BigInteger encrypt(BigInteger message);
    
     /**
     * decrypt an encrypted message through
     * <b>M = C^d mod n</b> where:
     *<ul>
     * <li>M = decrypted message
     * <li>C = encrypted message
     * <li>d = private key - obtained from multiplicative inverse of 'e' mod 'phi'
     * <li>n = modulo - obtained from p*q
     *</ul>
     * @param encrypted encrypted message
     * @return decrypted message
     */
    BigInteger decrypt(BigInteger encrypted);
    
    /**
     * digitally signs a message through
     * <b>A = M^d mod n</b> where:
     *<ul>
     * <li>A = signed message 
     * <li>M = message to be digitally signed 
     * <li>d = private key - obtained from multiplicative inverse of 'e' mod 'phi'
     * <li>n = modulo - obtained from p*q
     *</ul>
     * @param message to be digitally signed
     * @return signed message
     */
    BigInteger sign(BigInteger message);
    
     /**
     * verifies a signed message through
     * <b>A^e mod n = M</b> where:
     *<ul>
     * <li>A = signed message
     * <li>e = relative prime to phi
     * <li>n = modulo - obtained from p*q
     * <li>M = original message
     * </ul>
     * @param message to be verified
     * @return decimal number result from verification , 
     * if its equal to the decimal representation of the original
     * message then its successfully verified 
     * @see RSA#isVerified(java.math.BigInteger, java.math.BigInteger)
     * 
     */
    BigInteger Verify(BigInteger signedMessage);
    
     /**
     * @param signedMessage
     * @param original message 
     * @return <code>true</code> if decimal representation of the original message matched the decimal representation
     * of the signed message 
     * <code>false</code> otherwise
     * 
     * @see RSA#Verify(java.math.BigInteger) 
     */
    boolean isVerified(BigInteger signedMessage, BigInteger message);

    
}
