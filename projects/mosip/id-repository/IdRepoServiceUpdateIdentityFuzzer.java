import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * Module under test: id-repository-identity-service
 * Entry point: IdRepoServiceImpl.updateIdentity -- the logic behind the
 * update-identity endpoint, run for real. The controller harnesses fake this
 * layer; this one fakes the repositories behind it instead.
 *
 * Input: [request identity JSON] [0x00] [stored identity JSON]. See
 * IdRepoServiceFuzzSupport for the format, what is faked, what counts as a
 * finding, and the property checks. Seeds are in
 * seeds/IdRepoServiceUpdateIdentityFuzzer/ (binary, because of the NUL
 * separator).
 */
public class IdRepoServiceUpdateIdentityFuzzer {

    /**
     * Jazzer runs this once before libFuzzer's first timed unit, so the
     * expensive set-up (and the self-check) is not charged against the
     * 25-second per-unit timeout. See IdRepoControllerAddIdentityFuzzer.
     */
    public static void fuzzerInitialize() {
        IdRepoServiceFuzzSupport.init();
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        IdRepoServiceFuzzSupport.fuzzUpdate(data.consumeRemainingAsBytes());
    }
}
