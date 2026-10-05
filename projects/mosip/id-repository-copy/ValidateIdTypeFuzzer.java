import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.identity.validator.IdRequestValidator;

/**
 * Module under test: id-repository-identity-service
 * Target: IdRequestValidator.validateIdType(String)
 *
 * No mocking needed. The method body is just:
 *   IdType.valueOf(idType.toUpperCase())
 * wrapped in a try/catch that rethrows as IdRepoAppException -- no field
 * access at all, so it needs nothing beyond a bare instance.
 */
public class ValidateIdTypeFuzzer {

    private static final IdRequestValidator VALIDATOR = new IdRequestValidator();

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String idType = data.consumeRemainingAsString();
        try {
            VALIDATOR.validateIdType(idType);
        } catch (IdRepoAppException e) {
            // Expected: idType wasn't a valid IdType enum constant.
        }
    }
}
