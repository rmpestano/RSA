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
    
    
    BigInteger encrypt(BigInteger message);
    BigInteger decrypt(BigInteger encrypted);
    BigInteger sign(BigInteger message);
    BigInteger Verify(BigInteger signedMessage);
    boolean isVerified(BigInteger signedMessage, BigInteger message);

    
}
