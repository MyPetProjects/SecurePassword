package dao;

/**
 * Stub class used for testing {@link login.Login} class functionality
 * when there is no real database available
 * 
 * @author Valentine
 */
public class StorageStub implements Storage {
    /** stub salt value */
    private static final byte[] SALT = "B@5e13ad".getBytes();
    /** stub password value */
    private static final byte[] PASSWORD = "B@e2b07b".getBytes();
    
    /* (non-Javadoc)
     * @see dao.Storage#getSalt(java.lang.String)
     */
    @Override
    public byte[] getSalt(String login) {
        return SALT;
    };
    
    /* (non-Javadoc)
     * @see dao.Storage#getPassword(java.lang.String)
     */
    @Override
    public byte[] getPassword(String login) {
        return PASSWORD;
    };
    
    /* (non-Javadoc)
     * @see dao.Storage#storeLogin(java.lang.String, byte[], byte[])
     */
    @Override
    public boolean storeLogin(String login, byte[] password, byte[] salt) {
        return true;
    };
}
