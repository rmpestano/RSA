/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.ufrgs.rmpestano.rsa;

import java.math.BigInteger;
import java.util.List;

/**
 *
 * @author Rafael M. Pestano
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        BigInteger p;
        BigInteger q;
        BigInteger e;
        final String message;
        boolean isFile = false;
        if (args.length != 4) {//at leat four parametter should be given
            p = new BigInteger("5700734181645378434561188374130529072194886062117");
            q = new BigInteger("35894562752016259689151502540913447503526083241413");
            e = new BigInteger("33445843524692047286771520482406772494816708076993");
            message = "This is a test";
            
            //below are also valid primes
//          p = new BigInteger("101"); 
//          q = new BigInteger("113");
//          e = new BigInteger("3533");
        } else {
            p = new BigInteger(args[0]);
            q = new BigInteger(args[1]);
            e = new BigInteger(args[2]);
            if (args[3].contains("-f")) {
                isFile = true;
                message = args[3].substring(2);
            }
            else{
                message = args[3];
             }
        }
            

        RSA RSA = new RSAImpl(p, q, e);
        System.out.println(RSA);

        List<BigInteger> encryption;
        List<BigInteger> signed;
        List<BigInteger> decimalMessage;
        if(isFile){
            encryption = RSA.encryptFile(message);
            signed = RSA.signFile(message);
            decimalMessage = RSA.fileToDecimal(message);
        } else {
            encryption = RSA.encryptMessage(message);
            signed = RSA.signMessage(message);
            decimalMessage = RSA.messageToDecimal(message);
        }

        List<BigInteger> decrypt = RSA.decrypt(encryption);
        List<BigInteger> verify = RSA.verify(signed);
        System.out.println();
        System.out.println("message(plain text)   = " + Utils.bigIntegerToString(decimalMessage));
        System.out.println("message(decimal)      = " + Utils.bigIntegerSum(decimalMessage));
        System.out.println("encripted(decimal)    = " + Utils.bigIntegerSum(encryption));
        System.out.println("decrypted(plain text) = " + Utils.bigIntegerToString(decrypt));
        System.out.println("decrypted(decimal)    = " + Utils.bigIntegerSum(decrypt));
        System.out.println("signed(decimal)       = " + Utils.bigIntegerSum(signed));
        System.out.println("verified(plain text)  = " + Utils.bigIntegerToString(verify));
        System.out.println("verified(decimal)     = " + Utils.bigIntegerSum(verify));
    }
}
