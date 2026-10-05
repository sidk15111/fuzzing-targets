import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import io.mosip.idrepository.core.security.IdRepoSecurityManager;

/**
 * Module under test: id-repository-core
 * Target: IdRepoSecurityManager.hash(byte[])
 *
 * No mocking needed. hash() only calls the static HMACUtils2 utility and
 * never touches the restHelper field, so passing null to the constructor
 * (which is only used by the encrypt()/decrypt() methods we're not calling
 * here) is safe.
 */
public class HashFuzzer {

    private static final IdRepoSecurityManager SECURITY_MANAGER = new IdRepoSecurityManager(null);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        byte[] input = data.consumeRemainingAsBytes();
        SECURITY_MANAGER.hash(input);
    }
}
