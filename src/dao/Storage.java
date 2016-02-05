package dao;

/**
 * Stub class used for testing {@link login.Login} class functionality
 * when there is no real database available
 * 
 * @author Valentine
 */
public class Storage {
    /** stub salt value */
    private static final byte[] SALT = "B@5e13ad".getBytes();
    /** stub password value */
    private static final byte[] PASSWORD = "B@e2b07b".getBytes();
    
    /**
     * stub method which returns constant salt
     * 
     * @param  login not used for salt generation
     * @return constant salt value for testing
     */
    public byte[] getSalt(String login) {
        return SALT;
    };
    
    /**
     * returns correct hashed password for given login
     * 
     * @param login user login
     * @return constant password for testing
     */
    public byte[] getPassword(String login) {
        return PASSWORD;
    };
    
    /**
     * stub method which does nothing
     * 
     * @param  login user login
     * @param  password user password
     * @param  salt user salt
     * @return always true
     */
    public boolean storeLogin(String login, byte[] password, byte[] salt) {
        return true;
    };
}
