RSA example
===========

To run this program you will need to provide four arguments: p, q, e and message where:

  * p: a prime
  * q: another prime
  * e: a relative prime of (p-1) * (q-1) also know as phi(n)
  * m: a String message to be encriped, decriped and verified through a sighed certificate

if none of the inputs are provided the following values will be used as default:

  * p = "5700734181645378434561188374130529072194886062117"
  * q = "35894562752016259689151502540913447503526083241413"
  * e = "33445843524692047286771520482406772494816708076993"
  * m = "This is a test"

and the output will be:

  * p = 5700734181645378434561188374130529072194886062117
  * q = 35894562752016259689151502540913447503526083241413
  * e = 33445843524692047286771520482406772494816708076993
  * private = 183193943982723541083656360380592796925228591717543963697284925059702232695599866544519541421578897 (the generated private key)
  * modulus = 204625360815634094995873000754145818613880478081621272344332984978247528769851193693851726624851321 (pxq is used as modulus)

  * message(plain text)   = This is a test
  * message(decimal)      = 1711994770713785234952742657946484
  * encription(decimal)   = 139240771296277241521347552937648036139837396891313486473946673496820947584304910673718800610200595
  * decrypted(decimal)    = 1711994770713785234952742657946484
  * decrypted(plain text) = This is a test
  * signed(decimal)       = 10733204338670716957397445534002288521750891602329434749570348638974115725883468675924316514686531
  * verified(decimal)     = 1711994770713785234952742657946484
   
command to run: java -jar RSA.jar "101" "113" "3533" "Hello RSA"

to read from a file the last argument must be prefixed by a '-f' plus the path to the file containing the message to be encrypted, decrypted, signed and verified, here's an example:

java -jar RSA.jar "101" "113" "3533" "-f\home\rmpestano\rsa.txt"

RSA.jar can be found in [download section ](RSA/downloads)

Note that this implementation does not use any third party libs neither the 'java.security' package, its intend to be simple for academical learning . 
