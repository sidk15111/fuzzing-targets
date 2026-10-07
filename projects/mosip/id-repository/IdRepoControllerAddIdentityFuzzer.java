import org.springframework.test.web.servlet.MockMvc;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * Module under test: id-repository-identity-service
 * Entry point: IdRepoController.addIdentity (POST /) -- the create-identity
 * request.
 *
 * The fuzz input is used as the raw HTTP JSON body, so the full path runs:
 * Jackson deserialization into IdRequestDTO, the @InitBinder-registered
 * IdRequestValidator (requesttime, version, id, status, identity, documents),
 * UIN extraction via JsonPath, and the production exception handler.
 *
 * All wiring, the faked I/O edges, and the crash oracle live in
 * IdRepoFuzzSupport. Seeds are valid create requests in
 * seeds/IdRepoControllerAddIdentityFuzzer/.
 */
public class IdRepoControllerAddIdentityFuzzer {

    // Built once per process. Also runs a start-up self-check and fails
    // loudly if the harness wiring is wrong.
    private static final MockMvc MVC = IdRepoFuzzSupport.newMockMvc(false);

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        IdRepoFuzzSupport.fuzz(MVC, false, data.consumeRemainingAsBytes());
    }
}
