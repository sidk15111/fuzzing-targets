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
 *   - Add an entry ONLY after the bug is catalogued in the README ("Findings")
 *     with its crash file. Reporting upstream is separate.
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
     * IdRequestValidator.validateRequest() casts request.identity to a Map without
     * checking its type ("((Map) requestMap.get(ROOT_PATH)).isEmpty()", line 242 at
     * master 9332cc4), so a body whose "identity" is a string, number, array or
     * boolean throws ClassCastException. Reachable through the real front door:
     * Jackson binds "identity" as an untyped Object, and the schema validator only
     * runs after this cast. validate() reaches it even when requesttime, version
     * or id are invalid, because line 187 calls validateRequest() unconditionally.
     * Seen in the controller harnesses on ClusterFuzz (October 2026).
     */
    static final String VALIDATOR_IDENTITY_NOT_OBJECT = "validator-identity-not-object";


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
        if (t instanceof ClassCastException
                && VALIDATOR.equals(className) && "validateRequest".equals(methodName)
                && message != null && message.contains("java.util.Map")) {
            return VALIDATOR_IDENTITY_NOT_OBJECT;
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

    // Field names that occur inside an attribute's object in MOSIP's sample identity
    // schemas (simpleType, documentType, biometricsType). The schemas set
    // additionalProperties:false, so no other field name can reach the service.
    private static final java.util.Set<String> NESTED_FIELDS = new java.util.HashSet<>(java.util.Arrays.asList(
            "language", "value", "type", "format", "version", "fileReference", "label"));

    // Language codes are three lowercase letters (eng, ara, fra), not free text.
    private static final Pattern LANGUAGE_CODE = Pattern.compile("[a-z]{3}");

    static boolean isAttributeName(String key) {
        return ATTRIBUTE_NAME.matcher(key).matches();
    }

    static boolean isLanguageCode(String value) {
        return LANGUAGE_CODE.matcher(value).matches();
    }

    /**
     * True if a parsed identity (the request's, or the stored record) follows the
     * shapes that MOSIP's own sample identity schemas allow:
     *
     *   - every top-level attribute name matches ATTRIBUTE_NAME, and the fields inside
     *     an attribute's object are limited to the ones the sample schemas define
     *     (NESTED_FIELDS);
     *   - a top-level attribute is a scalar (string, number, boolean; never
     *     null), an object, or an array of objects;
     *   - those objects ("simpleType", "documentType", "biometricsType" in the
     *     sample schemas) hold scalars only, have a string "value", and a
     *     "language", if present, is a language code;
     *   - exceptions: "selectedHandles" may also be an array of strings, and
     *     "verifiedAttributes" is allowed only in the STORED record, as an array
     *     of strings (in a real request it is a sibling field of the identity).
     *
     * Attribute VALUES stay free text (names such as "O'Brien" are realistic).
     * This is an assumption modelled on the sample schemas, not the deployed one;
     * see README, "Input domain".
     */
    static boolean looksLikeRealIdentity(Object root) {
        return looksLikeRealIdentity(root, false);
    }

    static boolean looksLikeRealIdentity(Object root, boolean storedRecord) {
        if (!(root instanceof Map)) {
            return false;
        }
        for (Map.Entry<?, ?> top : ((Map<?, ?>) root).entrySet()) {
            if (!(top.getKey() instanceof String) || !isAttributeName((String) top.getKey())) {
                return false;
            }
            String name = (String) top.getKey();
            Object value = top.getValue();
            if ("verifiedAttributes".equals(name)) {
                if (!storedRecord || !isListOfStrings(value)) {
                    return false;
                }
            } else if ("selectedHandles".equals(name)) {
                if (!(value instanceof List)) {
                    return false; // by definition a list; a bare number or object is not a handle list
                }
                if (!isListOfStrings(value) && !isListOfValueObjects(value)) {
                    return false;
                }
            } else if (isScalar(value)) {
                continue;
            } else if (value instanceof Map) {
                if (!isValueObject((Map<?, ?>) value)) {
                    return false;
                }
            } else if (value instanceof List) {
                if (!isListOfValueObjects(value)) {
                    return false;
                }
            } else {
                return false; // null, or anything else
            }
        }
        return true;
    }

    private static boolean isScalar(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    private static boolean isListOfStrings(Object value) {
        if (!(value instanceof List)) {
            return false;
        }
        for (Object element : (List<?>) value) {
            if (!(element instanceof String)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isListOfValueObjects(Object value) {
        for (Object element : (List<?>) value) {
            if (!(element instanceof Map) || !isValueObject((Map<?, ?>) element)) {
                return false;
            }
        }
        return true;
    }

    // An object inside an attribute: scalar fields only, a string "value", and a
    // "language", when present, that is a language code.
    private static boolean isValueObject(Map<?, ?> object) {
        if (!(object.get("value") instanceof String)) {
            return false;
        }
        for (Map.Entry<?, ?> field : object.entrySet()) {
            if (!(field.getKey() instanceof String) || !NESTED_FIELDS.contains(field.getKey())
                    || !isScalar(field.getValue())) {
                return false;
            }
            if ("language".equals(field.getKey())
                    && !(field.getValue() instanceof String && isLanguageCode((String) field.getValue()))) {
                return false;
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
