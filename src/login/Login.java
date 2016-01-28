package login;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import dao.Storage;

public class Login {
    private static final int ITERATIONS = 1000;
    private static final int KEY_LENGTH = 160;
    private static final int SALT_SIZE = 8;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA1";
    private final Storage storage;

    public Login(Storage storage) {
        this.storage = storage;
    };
    
    private static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    };
    
    private static byte[] encryptPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                ITERATIONS, KEY_LENGTH);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    };

    public boolean register(String login, String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[SALT_SIZE];
        byte[] encPassword = encryptPassword(password, salt);
        return storage.storeLogin(login, encPassword, salt);
    }
    
    public boolean authenticate(String login, String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = storage.getSalt(login);
        byte[] encPassword = encryptPassword(password, salt);
        byte[] corrEncPassword = storage.getPassword(login);
        return Arrays.equals(encPassword, corrEncPassword);
    };
    
    public static void main(String[] args) {
        String password = "password";
        Login login = new Login(new Storage());
        try {
            byte[] salt = generateSalt();
            encryptPassword(password, salt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        };
    }
}
