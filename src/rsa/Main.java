/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import org.apache.commons.codec.DecoderException;

/**
 *
 * @author Rafael M. Pestano
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnsupportedEncodingException, DecoderException {
      BigInteger p;
      BigInteger q;
      BigInteger e;
      BigInteger message;
      if(args.length != 4){
          p = new BigInteger("5700734181645378434561188374130529072194886062117");
          q = new BigInteger("35894562752016259689151502540913447503526083241413");
          e = new BigInteger("33445843524692047286771520482406772494816708076993");
          message = new BigInteger("This is a test".getBytes());
//          p = new BigInteger("101");
//          q = new BigInteger("113");
//          e = new BigInteger("3533");
//          message = new BigInteger("9726");
      }
      else{
          p = new BigInteger(args[0]);
          q = new BigInteger(args[1]);
          e = new BigInteger(args[2]);
          message = new BigInteger(args[3]);
      }
      
      
      
      RSA RSA = new RSA(p,q,e);
      System.out.println(RSA);
 
      //// create message by converting string to integer
      // String s = "test";
      // byte[] bytes = s.getBytes();
      // BigInteger message = new BigInteger(s);
//      message = new BigInteger("t".getBytes());
      BigInteger encrypt = RSA.encrypt(message);
      BigInteger decrypt = RSA.decrypt(encrypt);
      BigInteger sign = RSA.sign(message);
      BigInteger verify = RSA.Verify(sign); 
      System.out.println("message(bytes)     = " +new String(message.toByteArray()));
      System.out.println("message(decimal)   = " + message);
      System.out.println("encrpyted          = " + encrypt);
      System.out.println("decrypted          = " + decrypt);
      System.out.println("signed             = " + sign);
      System.out.println("verify             = " + verify);
      System.out.println("verified           = " + RSA.isVerified(sign, message));
    }
}
