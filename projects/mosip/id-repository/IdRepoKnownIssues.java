import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

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


    /**
     * The update merge turns attribute NAMES from the request into JsonPath
     * expressions without escaping them (updateMissingFields,
     * updateFailingFields, updateMissingValues split on dots and rewrite
     * brackets and "="). A name containing a path character, such as
     * "a.b", is read as a path, so the merge looks for a parent that does not
     * exist and a JsonPath exception escapes updateIdentity.
     *
     * Unlike the entries above this one CANNOT be matched on the stack: JsonPath
     * deliberately throws these exceptions without a stack trace. It is matched
     * on context instead: a JsonPathException while the request names an
     * attribute containing a path character, at any depth. The property check in
     * IdRepoServiceFuzzSupport still runs on successful updates, so the more
     * serious form of this bug, a dotted name silently writing to the wrong
     * place, is still hunted.
     *
     * Reachability from the real API is NOT yet confirmed: the schema validator
     * may reject such attribute names.
     *
     * The service-level harness currently restricts attribute names to real-looking
     * ones (see looksLikeRealIdentity), so this entry cannot trigger there. It is
     * kept as documentation and for a dedicated hostile-name harness. Other
     * symptoms of the same root cause seen: an empty name throws
     * IllegalArgumentException "key can not be null or empty" from JsonPath.put in
     * updateMissingFields (line 687).
     */
    static final String UPDATE_KEY_NAMES_IN_JSONPATH = "update-key-names-in-jsonpath";

    // Characters that mean something in a JsonPath expression.
    private static final String PATH_CHARS = ".[]'?@*()=$";

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

    // ------------------------------------------------------------------ //
    //  Input domain of the service-level harness                           //
    // ------------------------------------------------------------------ //

    // What a real identity attribute name looks like (fullName, proofOfAddress,
    // addressLine1, ...). Anything else is assumed to be stopped by the real
    // front door (controller validation and the schema validator) before it
    // can reach the service. This is an ASSUMPTION; see README, "Input domain".
    private static final Pattern ATTRIBUTE_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_]{0,63}");

    // Language codes are three lowercase letters (eng, ara, fra), not free text.
    private static final Pattern LANGUAGE_CODE = Pattern.compile("[a-z]{3}");

    static boolean isAttributeName(String key) {
        return ATTRIBUTE_NAME.matcher(key).matches();
    }

    static boolean isLanguageCode(String value) {
        return LANGUAGE_CODE.matcher(value).matches();
    }

    /**
     * True if a parsed request identity stays inside the harness's input
     * domain: every key at any depth is an attribute name, and every "language"
     * value is a language code. Attribute VALUES are deliberately not
     * restricted (names such as "O'Brien" are realistic).
     */
    static boolean looksLikeRealIdentity(Object root) {
        Deque<Object> pending = new ArrayDeque<>();
        if (root != null) {
            pending.push(root);
        }
        while (!pending.isEmpty()) {
            Object node = pending.pop();
            if (node instanceof Map) {
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) node).entrySet()) {
                    if (!(entry.getKey() instanceof String) || !isAttributeName((String) entry.getKey())) {
                        return false;
                    }
                    Object value = entry.getValue();
                    if ("language".equals(entry.getKey()) && value instanceof String
                            && !isLanguageCode((String) value)) {
                        return false;
                    }
                    if (value != null) {
                        pending.push(value);
                    }
                }
            } else if (node instanceof List) {
                for (Object element : (List<?>) node) {
                    if (element != null) {
                        pending.push(element);
                    }
                }
            }
        }
        return true;
    }

    /**
     * Like match(), plus the entries that need context from the harness.
     * requestHasPathKey is hasPathSignificantKey(request identity), computed
     * BEFORE the call because the service may modify the map it is given.
     */
    static String matchUpdate(Throwable t, boolean requestHasPathKey) {
        String known = match(t);
        if (known != null) {
            return known;
        }
        if (requestHasPathKey && isInstanceOfNamed(t, "com.jayway.jsonpath.JsonPathException")) {
            return UPDATE_KEY_NAMES_IN_JSONPATH;
        }
        return null;
    }

    /** True if any KEY (not value) at any depth contains a JsonPath character. */
    static boolean hasPathSignificantKey(Object root) {
        // Iterative: the input can be nested very deeply. ArrayDeque rejects null,
        // and JSON null is common in this input, so nulls are skipped, never pushed.
        Deque<Object> pending = new ArrayDeque<>();
        if (root != null) {
            pending.push(root);
        }
        while (!pending.isEmpty()) {
            Object node = pending.pop();
            if (node instanceof Map) {
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) node).entrySet()) {
                    if (entry.getKey() instanceof String && containsPathChar((String) entry.getKey())) {
                        return true;
                    }
                    if (entry.getValue() != null) {
                        pending.push(entry.getValue());
                    }
                }
            } else if (node instanceof List) {
                for (Object element : (List<?>) node) {
                    if (element != null) {
                        pending.push(element);
                    }
                }
            }
        }
        return false;
    }

    private static boolean containsPathChar(String key) {
        for (int i = 0; i < key.length(); i++) {
            if (PATH_CHARS.indexOf(key.charAt(i)) >= 0) {
                return true;
            }
        }
        return false;
    }

    // By class name, so this file needs no JsonPath dependency to compile.
    private static boolean isInstanceOfNamed(Throwable t, String className) {
        for (Class<?> c = t.getClass(); c != null; c = c.getSuperclass()) {
            if (c.getName().equals(className)) {
                return true;
            }
        }
        return false;
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
