import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import io.mosip.idrepository.core.security.IdRepoSecurityManager;

/**
 * Module under test: id-repository-core
 * Target: IdRepoSecurityManager.hashwithSalt(byte[], byte[])
 *
 * No mocking needed, same reasoning as HashFuzzer. The fuzz input is split
 * into two byte arrays (a bounded-length salt, then the remaining data) so
 * both arguments vary independently from run to run instead of always
 * pairing an empty salt with the full input.
 */
public class HashWithSaltFuzzer {

    private static final IdRepoSecurityManager SECURITY_MANAGER = new IdRepoSecurityManager(null);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int saltLen = data.consumeInt(0, 64);
        byte[] salt = data.consumeBytes(saltLen);
        byte[] value = data.consumeRemainingAsBytes();
        SECURITY_MANAGER.hashwithSalt(value, salt);
    }
}
