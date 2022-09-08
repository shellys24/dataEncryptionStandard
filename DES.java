import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


class DES {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        //String we want to encrypt
        String message = "This message is confidential!";
        byte[] myMessage = message.getBytes(); //string to byte array as DES works on bytes

        //If you want to use your own key
        // SecretKeyFactory MyKeyFactory = SecretKeyFactory.getInstance("DES");
        // String Password = "My Password";
        // byte[] myByte =Password.getBytes();
        // DESKeySpec myMaterial = new DESKeySpec(myByte);
        // SecretKey myDESKey = MyKeyFactory.generateSecret(myMaterial);

        //Generating Key
        KeyGenerator myGenerator = KeyGenerator.getInstance("DES");
        SecretKey myDesKey = myGenerator.generateKey();


        Cipher myCipher = Cipher.getInstance("DES");

        //setting encryption mode
        myCipher.init(Cipher.ENCRYPT_MODE, myDesKey);
        byte[] myEncryptedBytes = myCipher.doFinal(myMessage);


        //setting decryption mode
        myCipher.init(Cipher.DECRYPT_MODE, myDesKey);
        byte[] myDecryptedBytes = myCipher.doFinal(myEncryptedBytes);

        //print message in byte format
        System.out.println(Arrays.toString(myEncryptedBytes));
        System.out.println(Arrays.toString(myDecryptedBytes));

        String encryptData = new String(myEncryptedBytes);
        String decryptData = new String(myDecryptedBytes);

        System.out.println("Message : " + message);
        System.out.println("Encrypted Message - " + encryptData);
        System.out.println("Decrypted Message - " + decryptData);
    }
}


