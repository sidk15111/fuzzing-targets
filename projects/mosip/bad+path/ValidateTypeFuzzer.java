import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.identity.validator.IdRequestValidator;

/**
 * Module under test: id-repository-identity-service
 * Target: IdRequestValidator.validateType(String)
 *
 * No mocking needed. validateType() only reads the `allowedTypes` field,
 * which is set by a plain field initializer in the class
 * (private List<String> allowedTypes = List.of("bio","demo",...)), not by
 * @Autowired -- so it's already populated on a bare `new IdRequestValidator()`
 * with no Spring context at all.
 */
public class ValidateTypeFuzzer {

    private static final IdRequestValidator VALIDATOR = new IdRequestValidator();

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String type = data.consumeRemainingAsString();
        try {
            VALIDATOR.validateType(type);
        } catch (IdRepoAppException e) {
            // Expected: validator correctly rejected a disallowed/malformed type.
        }
    }
}
