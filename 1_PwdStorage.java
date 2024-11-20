import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PwdStorage {
    private static String ALGORITHM = "PBEWithMD5AndDES"; // algorithm and mode
    private static int ITERATIONS = 1000;  // cycles per password guess an attacker needs
    private static int KEYLENGTH = 16;     // bytes
    private static int SALTLENGTH = 8;     // bytes 
    private static String SEPARATOR = ":"; // Separation character

    // generate a random salt
    private static byte[] generateSalt() {
        byte[] salt = new byte[SALTLENGTH];
        Random sr = new Random();
        sr.nextBytes(salt);
        return salt;
    }

    // generate storable version of entered password
    public static String generateStorablePassword(String plaintextPwd, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec ks = new PBEKeySpec(
                plaintextPwd.toCharArray(),
                salt,
                ITERATIONS,
                KEYLENGTH * Byte.SIZE);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        byte[] pwdHash = keyFactory.generateSecret(ks).getEncoded();

        return ALGORITHM + SEPARATOR + 
               ITERATIONS + SEPARATOR + 
               Base64.getEncoder().encodeToString(salt) + SEPARATOR +
               Base64.getEncoder().encodeToString(pwdHash);
    }

    // compare hash values of two keys
    private static boolean compareHashValues(byte[] a, byte[] b) {
        return Arrays.equals(a, b);
    }

    // verify if entered password matches dbEntry
    public static boolean checkPassword(String plaintextPwd, String dbEntry)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] elements = dbEntry.split(SEPARATOR);
        String algorithm = elements[0];
        int iterations = Integer.parseInt(elements[1]);
        byte[] salt = Base64.getDecoder().decode(elements[2]);
        byte[] dbHash = Base64.getDecoder().decode(elements[3]);

        PBEKeySpec ks = new PBEKeySpec(
                plaintextPwd.toCharArray(),
                salt,
                iterations,
                dbHash.length * Byte.SIZE);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
        byte[] newHash = keyFactory.generateSecret(ks).getEncoded();

        return compareHashValues(dbHash, newHash);
    }

    public static void main(String[] args) {
        // test if it really works
        try {
            byte[] salt = generateSalt();
            String dbEntry = PwdStorage.generateStorablePassword("myTestPwd", salt);
            System.out.println(dbEntry);
            System.out.println(checkPassword("myTestPwd1", dbEntry)); // False
            System.out.println(checkPassword("myTestPw", dbEntry)); // False
            System.out.println(checkPassword("myTestPwd", dbEntry)); // True
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("An error occured");
        }
    }
}