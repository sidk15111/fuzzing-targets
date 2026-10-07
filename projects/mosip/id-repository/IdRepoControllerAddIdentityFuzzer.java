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

    private static MockMvc mvc;

    /**
     * Jazzer calls this once, BEFORE libFuzzer starts its first unit. The
     * set-up is expensive (Spring MVC, Mockito, the start-up self-check, and
     * Jazzer instrumenting hundreds of freshly loaded classes), so it must not
     * happen lazily inside fuzzerTestOneInput: libFuzzer's 25-second per-unit
     * timeout would then count it against the very first input. That is
     * exactly what failed check_build on the slower build bot.
     */
    public static void fuzzerInitialize() {
        mvc = IdRepoFuzzSupport.newMockMvc(false);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        IdRepoFuzzSupport.fuzz(mvc, false, data.consumeRemainingAsBytes());
    }
}
