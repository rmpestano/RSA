/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.ufrgs.rmpestano.rsa;

import java.math.BigInteger;

/**
 * Implementation of RSA encription algorithm http://en.wikipedia.org/wiki/RSA_(algorithm  
 * 
 * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
 */
public class RSAImpl implements RSA {

    private final static BigInteger ONE = new BigInteger("1");
    private BigInteger privateKey;
    private BigInteger e; //part of public key - relative prime of phi 
    private BigInteger modulus; //part of public key obtained with n = p*q
    private BigInteger p; //prime
    private BigInteger q; //prime
    private final BigInteger phi;// obtained with phi = (p-1)*(q-1)
    
    RSAImpl(BigInteger p, BigInteger q, BigInteger e) {
        
        phi = (p.subtract(ONE)).multiply(q.subtract(ONE)); //phi = (p-1)*(q-1) 
        this.e = e;
        this.p = p;
        this.q = q;
        modulus = p.multiply(q); 
        privateKey = e.modInverse(phi);//d = e^-1 mod phi, private key is obtained with the multiplative inverse of 'e' mod 'phi'
    }

   
    @Override
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, modulus);        
    }
   
    @Override
    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(privateKey, modulus);
    }

    @Override
    public BigInteger sign(BigInteger message) {
        return message.modPow(privateKey, modulus);
    }

    @Override
    public BigInteger Verify(BigInteger signedMessage) {
        return signedMessage.modPow(e, modulus);
    }
    
   
    @Override
    public boolean isVerified(BigInteger signedMessage, BigInteger message) {
        return this.Verify(signedMessage).equals(message);
    }
    
    //getter & setters
    
    /**
     * private key is obtained with the multiplicative inverse of 'e' mod 'phi'
     * @return private key
     */
    public BigInteger getPrivateKey() {
        return privateKey;
    }
    
    public BigInteger getE() {
        return e;
    }
    
    public BigInteger getModulus() {
        return modulus;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }
    
    
    public BigInteger getP() {
        return p;
    }
    
    public BigInteger getQ() {
        return q;
    }
    
    public BigInteger getPhi() {
        return phi;
    }
    
    @Override
    public String toString() {
        String s = "";
        s += "p                  = " + p + "\n";
        s += "q                  = " + q + "\n";
        s += "e                  = " + e + "\n";
        s += "private            = " + privateKey + "\n";
        s += "modulus            = " + modulus;
        return s;
    }
}
