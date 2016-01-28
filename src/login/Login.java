package login;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
    
    private static byte[] generateSalt() throws Exception {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[SALT_SIZE];
            random.nextBytes(salt);
            return salt;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new Exception("Internal error occured in encrypting module!" +
                        "Salt generating failed!");
        }
    };
    
    private static byte[] encryptPassword(String password, byte[] salt)
            throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                ITERATIONS, KEY_LENGTH);
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new Exception("Internal error occured in encrypting module!");
        }
    };

    public boolean register(String login, String password) {
        byte[] salt = new byte[SALT_SIZE];
        try {
            salt = generateSalt();
            byte[] encPassword = encryptPassword(password, salt);
            return storage.storeLogin(login, encPassword, salt);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean authenticate(String login, String password) {
        byte[] salt = storage.getSalt(login);
        try {
            byte[] encPassword = encryptPassword(password, salt);
            byte[] corrEncPassword = storage.getPassword(login);
            return Arrays.equals(encPassword, corrEncPassword);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    };
    
    public void userInterface() {
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in));
        System.out.println("Register new user - 1");
        System.out.println("Login - 2");
        try {
            String userResponse = reader.readLine();
            if (userResponse == "1") {
                System.out.println("Input login");
                String loginStr = reader.readLine();
                System.out.println("Input password");
                String passwordStr = reader.readLine();
                if (register(loginStr, passwordStr)) {
                    System.out.printf("User %s registered successfully!\n", loginStr);
                } else {
                    System.err.println("Failed to register a new user");
                };
            } else if (userResponse == "2") {
                System.out.println("Input login");                
                String loginStr = reader.readLine();
                System.out.println("Input password");                
                String passwordStr = reader.readLine();                
                if (authenticate(loginStr, passwordStr)) {
                    System.out.printf("Hello, %s!\n", loginStr);
                } else {
                    System.err.println("Incorrect login or password!");
                };
            } else {
                System.exit(0);
            };
        } catch (IOException e1) {
            System.err.println("Error! Input/output crashed!");
            e1.printStackTrace();
        };        
    };
    
    public static void main(String[] args) {
        Login login = new Login(new Storage());
        login.userInterface();
    };
};
