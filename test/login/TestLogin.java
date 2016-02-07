/**
 * 
 */
package login;

import static org.junit.Assert.*;

import org.junit.Test;

import dao.Storage;
import dao.StorageStub;

/**
 * @author Valentine
 *
 */
public class TestLogin {
    @Test
    public void testAuthenticate() {
        Storage storageStub = new StorageStub();
        Login login = new Login(storageStub);
        assertTrue(login.authenticate("any login", "password"));
    }
}
