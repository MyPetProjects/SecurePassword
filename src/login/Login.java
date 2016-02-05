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

/**
 * Login is used to register new users and to authenticate existing ones
 * using {@link dao.Storage} provided at creation time
 * 
 * @author Valentine
 */
public class Login {
    /** number of iterations used in password-based encryption(PBE) */
    private static final int ITERATIONS = 1000;
    /** key length in password-based encryption(PBE) */
    private static final int KEY_LENGTH = 160;
    /**  Random Number Generator (RNG) algorithm used in salt generation */
    private static final String SALT_ALGORITHM = "SHA1PRNG";
    /** salt length (in bytes) */
    private static final int SALT_SIZE = 8;
    /** secret-key algorithm used in password encryption */
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    private final Storage storage;

    /**
     * @param storage storage with login information
     */
    public Login(Storage storage) {
        this.storage = storage;
    };
    
    /**
     * generates random number(salt) for further password encryption
     * 
     * @return unique randomly generated salt in form of array of bytes
     * @throws NoSuchAlgorithmException if incorrect algorithm
     *         is used for salt generation
     */
    private static byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance(SALT_ALGORITHM);
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    };
    
    /**
     * encrypts password using provided salt
     * 
     * @param  password unencrypted password
     * @param  salt random number which increases encryption
     *         safety(should be unique for every login)
     * @return encrypted password
     * @throws Exception if encryption settings are incorrect
     */
    private static byte[] encryptPassword(String password, byte[] salt)
            throws Exception {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt,
                ITERATIONS, KEY_LENGTH);
        try {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
            SecretKey secretKey = keyFactory.generateSecret(keySpec);
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            throw new Exception("Internal error occured in encrypting module!");
        }
    };

    /**
     * registers a new user
     * 
     * @param  login user login
     * @param  password user password
     * @return true if user registered successfully
     *         false if some error occured
     */
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
    
    /**
     * checks the validity of login and password type
     * 
     * @param  login login of existing user
     * @param  password password of existing user
     * @return true if provided user login and password are correct
     *         false if login or password are incorrect or if an error
     *         happened during authentication 
     */
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
    
    /**
     * provides console interface for user authentication
     */
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
    
    /**
     * entry point to application
     * @param args no command line arguments are expected
     */
    public static void main(String[] args) {
        Login login = new Login(new Storage());
        login.userInterface();
    };
};
