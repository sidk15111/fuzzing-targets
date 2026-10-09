import java.util.HashMap;
import java.util.Map;

/**
 * Registry of known bugs in MOSIP's id-repository that are already reported
 * upstream but still present in master. Shared by the controller-level and
 * service-level harnesses.
 *
 * NOT a fuzz target: the name does not end in "Fuzzer".
 *
 * Why this exists: a shallow bug at the front of a code path ends every
 * fuzzing session within minutes (libFuzzer stops at the first crash) and
 * hides everything behind it. Listing it here lets the fuzzer skip it and
 * keep going.
 *
 * Rules:
 *   - Add an entry ONLY after the bug has been reported upstream.
 *   - Delete the entry when upstream fixes it, so a regression is caught.
 *   - Match on exception type, the throwing method and, where it helps, the
 *     message. NEVER on line numbers, which drift whenever upstream edits.
 *   - Keep each entry as narrow as the root cause allows.
 *
 * Matching uses the FIRST MOSIP frame in the stack (class name starting with
 * "io.mosip."), not the top frame. A bug inside a JDK call made by MOSIP code
 * has a JDK frame on top (for example ArrayList.forEach for a bad cast inside
 * a lambda); the first MOSIP frame is still the method that caused it.
 *
 * Stack traces matter: the wrapper script runs the JVM with
 * -XX:-OmitStackTraceInFastThrow because HotSpot can strip the stack from an
 * exception thrown many times. A stripped exception has no MOSIP frame, is
 * therefore NOT matched, and surfaces as a finding instead of being hidden.
 */
public final class IdRepoKnownIssues {

    /**
     * IdRequestValidator.validate() calls request.getRequest().<something>
     * without checking that "request" is present, so a body with no "request"
     * object throws NullPointerException. Seen in the controller harnesses.
     */
    static final String VALIDATOR_NULL_REQUEST = "validator-null-request";

    /**
     * IdRepoServiceImpl.updateRequestBodyData() trims attribute values (the
     * default configuration, trim-whitespaces=true) but casts them without
     * checking their shape: a list element that is not an object, an object
     * with no "value", a "value" that is not a string, or a null value all
     * throw ClassCastException or NullPointerException. One entry covers the
     * whole method because they share one root cause and fixing one without
     * the others would just expose the next.
     *
     * Reachability from the real API is NOT yet confirmed: the schema
     * validator in front of the service may reject these shapes.
     */
    static final String UPDATE_TRIM_UNCHECKED_CASTS = "update-trim-unchecked-casts";

    private static final String VALIDATOR = "io.mosip.idrepository.identity.validator.IdRequestValidator";
    private static final String SERVICE = "io.mosip.idrepository.identity.service.impl.IdRepoServiceImpl";

    private static final Map<String, Long> hits = new HashMap<>();

    private IdRepoKnownIssues() {
    }

    /** Returns the id of the known issue this exception is, or null. */
    static String match(Throwable t) {
        StackTraceElement frame = firstMosipFrame(t);
        if (frame == null) {
            return null;
        }
        String className = frame.getClassName();
        String methodName = frame.getMethodName();
        String message = t.getMessage();

        if (t instanceof NullPointerException
                && VALIDATOR.equals(className) && "validate".equals(methodName)
                && message != null && message.contains("IdRequestDTO.getRequest()")) {
            return VALIDATOR_NULL_REQUEST;
        }
        // contains(), not equals(): the failing cast is usually inside a lambda,
        // whose method is named like "lambda$updateRequestBodyData$3".
        if ((t instanceof ClassCastException || t instanceof NullPointerException)
                && SERVICE.equals(className) && methodName.contains("updateRequestBodyData")) {
            return UPDATE_TRIM_UNCHECKED_CASTS;
        }
        return null;
    }

    /** Counts a hit; prints one line per issue per process, then stays silent. */
    static void note(String id) {
        long count = hits.merge(id, 1L, Long::sum);
        if (count == 1) {
            System.err.println("IdRepoKnownIssues: skipping known issue '" + id
                    + "' (see README, Known issues). Further hits are counted silently.");
        }
    }

    private static StackTraceElement firstMosipFrame(Throwable t) {
        for (StackTraceElement frame : t.getStackTrace()) {
            if (frame.getClassName().startsWith("io.mosip.")) {
                return frame;
            }
        }
        return null;
    }
}
