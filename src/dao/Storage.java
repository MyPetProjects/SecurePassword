package dao;

/**
 * Interface for storing and obtaining user authenticating info:
 * login, password and salt to/from underlying storage
 * 
 * @author Valentine
 */
public interface Storage {
    /**
     * returns salt for provided login
     * 
     * @param  login login for which we want obtain salt
     * @return salt value unique for every login and used for password encryption
     */
    byte[] getSalt(String login);

    /**
     * returns correct hashed password for given login
     * 
     * @param login user login
     * @return correct hashed password for given login
     */
    byte[] getPassword(String login);

    /**
     * stores user login, password and salt in the storage
     * 
     * @param  login user login
     * @param  password user password
     * @param  salt user salt
     * @return true if user info has been successfully stored
     *         false if some error occured
     */
    boolean storeLogin(String login, byte[] password, byte[] salt);
}