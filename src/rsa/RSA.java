/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author Rafael M. Pestano - Oct 15, 2012 7:15:19 PM
 */
public class RSA {
   private final static BigInteger ONE      = new BigInteger("1");
   private final static SecureRandom random = new SecureRandom();

   private BigInteger privateKey;
   private BigInteger e; //chave publica
   private BigInteger modulus; //chave publica
   private BigInteger p;
   private BigInteger q;

   
   RSA(BigInteger p, BigInteger q, BigInteger e) {
       
      BigInteger phi = (p.subtract(ONE)).multiply(q.subtract(ONE)); //phi = (p-1)*(q-1) 
      this.e = e; //primo relativo a phi
      this.p = p;
      this.q = q;
      modulus    = p.multiply(q); // modulo é obtido a partir da multiplicação de p e q                                
      privateKey = e.modInverse(phi);//d = e-1 mod phi, inverso multiplicativo em modulo do primo relativo
   }


   /**
    * 
    * C = M^e mod n onde:
    * 
    * C = mensagem cifrada
    * M = mensagem a ser encriptada
    * e = primo relativo a phi 
    * n = modulo calculado a partir da multiplicação dos primos p e q
    * 
        * @param message
    * @return mensagem cifrada
    */
   BigInteger encrypt(BigInteger message) {
      return message.modPow(e, modulus);  
   }

   /**
    * M = C^d mod n onde:
    * 
    * M = mensagem decriptada
    * C = mensagem encriptada
    * d = chave privada calculada a partir do inverso multiplicativo de e mod phi
    * n = modulo calculado a partir da multiplicação dos primos p e q
    * 
    * @param encrypted mensagem encriptada
    * @return mensagem decriptada
    */
   BigInteger decrypt(BigInteger encrypted) {
      return encrypted.modPow(privateKey, modulus);
   }
   
   /**
    * A = M^d mod n onde
    * 
    * A = mensagem assinada
    * M = mensagem a ser assinada
    * d = chave privada calculada a partir do inverso multiplicativo de e mod phi
    * n = modulo calculado a partir da multiplicação dos primos p e q
    * 
    * @param message
    * @return messagem assinada
    */
   BigInteger sign(BigInteger message){
       return message.modPow(privateKey, modulus);
   }
   
   /**
    * aplica metodo de verificação de assinatura através de A^e mod n = M  
    * onde: 
    * A = mensagem assinada
    * e = primo relativo a phi 
    * n = modulo calculado a partir da multiplicação dos primos p e q
    * M = mensagem original
    * 
    * @param message
    * @return resultado(decimal) da verificação 
    * 
    */
   BigInteger Verify(BigInteger signedMessage){
       return signedMessage.modPow(e, modulus);
   }
   
   public boolean isVerified(BigInteger signedMessage, BigInteger message){
       return this.Verify(signedMessage).equals(message);
   }
   

   @Override
   public String toString() {
      String s = "";
      s += "p                  = " + p+ "\n";
      s += "q                  = " + q+ "\n";
      s += "e                  = " + e  + "\n";
      s += "private            = " + privateKey + "\n";
      s += "modulus            = " + modulus;
      return s;
   }

    public BigInteger getModulus() {
        return modulus;
    }
   

}
