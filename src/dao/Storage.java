package dao;

public class Storage {
    private static final byte[] SALT = "B@5e13ad".getBytes();
    private static final byte[] PASSWORD = "B@e2b07b".getBytes();
    
    public byte[] getSalt(String login) {
        return SALT;
    };
    
    public byte[] getPassword(String login) {
        return PASSWORD;
    };
    
    public boolean storeLogin(String login, byte[] password, byte[] salt) {
        return true;
    };
}
