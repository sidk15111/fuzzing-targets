import org.springframework.test.web.servlet.MockMvc;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * Module under test: id-repository-identity-service
 * Entry point: IdRepoController.updateIdentity (PATCH /) -- the
 * update-identity request.
 *
 * Same path and oracle as IdRepoControllerAddIdentityFuzzer, but for the
 * update operation: the request id must be the "update" id, and a request
 * "status", if present, must be one of the configured UIN statuses. See
 * IdRepoFuzzSupport for the wiring. Seeds are valid update requests in
 * seeds/IdRepoControllerUpdateIdentityFuzzer/.
 */
public class IdRepoControllerUpdateIdentityFuzzer {

    private static final MockMvc MVC = IdRepoFuzzSupport.newMockMvc(true);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        IdRepoFuzzSupport.fuzz(MVC, true, data.consumeRemainingAsBytes());
    }
}
