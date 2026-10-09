import static org.mockito.Mockito.RETURNS_DEFAULTS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.slf4j.LoggerFactory;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.test.util.ReflectionTestUtils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.idrepository.core.dto.IdRequestDTO;
import io.mosip.idrepository.core.dto.RequestDTO;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.exception.IdRepoAppUncheckedException;
import io.mosip.idrepository.core.repository.CredentialRequestStatusRepo;
import io.mosip.idrepository.core.repository.HandleRepo;
import io.mosip.idrepository.core.repository.UinEncryptSaltRepo;
import io.mosip.idrepository.core.repository.UinHashSaltRepo;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.idrepository.core.util.DummyPartnerCheckUtil;
import io.mosip.idrepository.core.util.EnvUtil;
import io.mosip.idrepository.identity.entity.Uin;
import io.mosip.idrepository.identity.helper.AnonymousProfileHelper;
import io.mosip.idrepository.identity.helper.IdRepoServiceHelper;
import io.mosip.idrepository.identity.helper.ObjectStoreHelper;
import io.mosip.idrepository.identity.provider.IdentityUpdateTrackerPolicyProvider;
import io.mosip.idrepository.identity.repository.IdentityUpdateTrackerRepo;
import io.mosip.idrepository.identity.repository.UinBiometricHistoryRepo;
import io.mosip.idrepository.identity.repository.UinDocumentHistoryRepo;
import io.mosip.idrepository.identity.repository.UinHistoryRepo;
import io.mosip.idrepository.identity.repository.UinRepo;
import io.mosip.idrepository.identity.service.impl.IdRepoServiceImpl;
import io.mosip.kernel.biometrics.spi.CbeffUtil;

/**
 * Shared wiring for the service-level harnesses (currently
 * IdRepoServiceUpdateIdentityFuzzer).
 *
 * NOT a fuzz target: the name does not end in "Fuzzer", so build.sh does not
 * wrap it and project.yaml does not list it.
 *
 * Where the controller-level harnesses run MOSIP's controller and validator
 * and fake the service, this one runs the REAL IdRepoServiceImpl and fakes
 * what sits behind it:
 *
 *   REAL : IdRepoServiceImpl (the update/merge logic, JsonPath and
 *          JSONCompare handling, update-count tracking, credential
 *          bookkeeping), IdRepoSecurityManager hashing, IdRepoServiceHelper
 *   FAKED: every repository (the stored identity comes from the fuzz input),
 *          the object store, CBEFF handling, anonymous-profile helper,
 *          partner lookup
 *
 * Input: [request identity JSON] [0x00] [stored identity JSON]. Everything up
 * to the first NUL byte is the identity object the client sends; everything
 * after it is the record already in the database. With no NUL byte a default
 * stored record is used, so the fuzzer can focus on the request side.
 *
 * What counts as a finding:
 *   1. Any exception other than IdRepoAppException / IdRepoAppUncheckedException
 *      (MOSIP's own, intended error types): NullPointerException,
 *      ClassCastException, JsonPath exceptions escaping, and so on.
 *   2. A broken property after a SUCCESSFUL update (see checkProperties):
 *      the stored record is no longer a JSON object, its hash does not match,
 *      or an attribute the request did NOT name was changed, added or lost.
 *
 * Reachability: this calls the service directly, bypassing the controller's
 * validation and the schema validator. A finding here is a candidate. Before
 * reporting it, check whether the real request path could deliver that input
 * to the service.
 */
public final class IdRepoServiceFuzzSupport {

    private static final String UIN = "2419762130";
    private static final String REG_ID = "10001100010000620200101000000";
    private static final String VERIFIED_ATTRIBUTES = "verifiedAttributes";

    private static final ObjectMapper MAPPER = Jackson2ObjectMapperBuilder.json().build();
    private static final IdRepoSecurityManager SECURITY = new IdRepoSecurityManager(null);

    // Package-private on purpose: the fake repository reads currentStored, and
    // saveCalls lets the start-up self-check prove the update ran to the end.
    static Uin currentStored;
    static long saveCalls;

    private static IdRepoServiceImpl service;
    private static byte[] defaultStored;

    private IdRepoServiceFuzzSupport() {
    }

    // ------------------------------------------------------------------ //
    //  Wiring                                                              //
    // ------------------------------------------------------------------ //

    /** Builds the service once per process, then runs the self-check. */
    public static void init() {
        silenceLogging();

        // Static configuration Spring normally fills from properties.
        EnvUtil.setIdrepoSaltKeyLength(3);
        // In production this map is read from a URL at start-up. Attribute
        // names and limits here only need to be plausible.
        ReflectionTestUtils.setField(IdentityUpdateTrackerPolicyProvider.class, "updateCount",
                Map.of("fullName", 3, "dateOfBirth", 1, "phone", 5));

        defaultStored = loadResource("/identity-stored.json");
        service = buildService();
        selfCheck();
    }

    private static IdRepoServiceImpl buildService() {
        IdRepoServiceHelper helper = new IdRepoServiceHelper();
        ReflectionTestUtils.setField(helper, "mapper", MAPPER);

        IdRepoServiceImpl s = new IdRepoServiceImpl();
        ReflectionTestUtils.setField(s, "env", stub(EnvUtil.class));
        ReflectionTestUtils.setField(s, "mapper", MAPPER);
        ReflectionTestUtils.setField(s, "uinRepo", fakeUinRepo());
        ReflectionTestUtils.setField(s, "uinDocHRepo", stub(UinDocumentHistoryRepo.class));
        ReflectionTestUtils.setField(s, "uinBioHRepo", stub(UinBiometricHistoryRepo.class));
        ReflectionTestUtils.setField(s, "uinHistoryRepo", stub(UinHistoryRepo.class));
        ReflectionTestUtils.setField(s, "cbeffUtil", stub(CbeffUtil.class));
        ReflectionTestUtils.setField(s, "securityManager", SECURITY);
        ReflectionTestUtils.setField(s, "bioAttributes", new ArrayList<String>());
        ReflectionTestUtils.setField(s, "uinHashSaltRepo", fakeSaltRepo());
        ReflectionTestUtils.setField(s, "uinEncryptSaltRepo", stub(UinEncryptSaltRepo.class));
        ReflectionTestUtils.setField(s, "objectStoreHelper", stub(ObjectStoreHelper.class));
        ReflectionTestUtils.setField(s, "dummyPartner", stub(DummyPartnerCheckUtil.class));
        ReflectionTestUtils.setField(s, "credRequestRepo", stub(CredentialRequestStatusRepo.class));
        ReflectionTestUtils.setField(s, "anonymousProfileHelper", stub(AnonymousProfileHelper.class));
        // mosip.idrepo.identity.uin-status.registered
        ReflectionTestUtils.setField(s, "activeStatus", "ACTIVATED");
        // mosip.idrepo.update-identity.fields-to-replace
        ReflectionTestUtils.setField(s, "fieldsToReplaceOnUpdate", new ArrayList<>(List.of("selectedHandles")));
        ReflectionTestUtils.setField(s, "identityUpdateTracker", stub(IdentityUpdateTrackerRepo.class));
        ReflectionTestUtils.setField(s, "enableConventionBasedId", false);
        ReflectionTestUtils.setField(s, "handleRepo", stub(HandleRepo.class));
        ReflectionTestUtils.setField(s, "idRepoServiceHelper", helper);
        ReflectionTestUtils.setField(s, "uinRefId", "uinRefId");
        // mosip.idrepo.update-identity.trim-whitespaces defaults to true
        ReflectionTestUtils.setField(s, "trimWhitespaces", true);
        return s;
    }

    // stubOnly(): normal Mockito mocks record every call for verify(), which
    // grows the heap without bound over millions of fuzz iterations.
    private static <T> T stub(Class<T> type) {
        return mock(type, withSettings().stubOnly());
    }

    // The only repository whose answers matter: it hands the service the
    // stored record built from the fuzz input, and returns what is saved.
    private static UinRepo fakeUinRepo() {
        return mock(UinRepo.class, withSettings().stubOnly().defaultAnswer(invocation -> {
            switch (invocation.getMethod().getName()) {
            case "findByUinHash":
                return Optional.of(currentStored);
            case "save":
                saveCalls++;
                return invocation.getArgument(0);
            default:
                return RETURNS_DEFAULTS.answer(invocation);
            }
        }));
    }

    private static UinHashSaltRepo fakeSaltRepo() {
        return mock(UinHashSaltRepo.class, withSettings().stubOnly().defaultAnswer(invocation ->
                "retrieveSaltById".equals(invocation.getMethod().getName())
                        ? "salt"
                        : RETURNS_DEFAULTS.answer(invocation)));
    }

    private static byte[] loadResource(String name) {
        try (InputStream in = IdRepoServiceFuzzSupport.class.getResourceAsStream(name)) {
            if (in == null) {
                throw new IllegalStateException(name + " is not on the classpath. "
                        + "It is copied from fixtures/ into $OUT by build.sh.");
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("Could not read " + name, e);
        }
    }

    // The service logs an error for every rejected update, which would
    // dominate run time. Reflective so a different logging backend does not
    // break the harness.
    private static void silenceLogging() {
        try {
            Class<?> levelClass = Class.forName("ch.qos.logback.classic.Level");
            Class<?> loggerClass = Class.forName("ch.qos.logback.classic.Logger");
            Object off = levelClass.getField("OFF").get(null);
            Object root = LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
            if (loggerClass.isInstance(root)) {
                loggerClass.getMethod("setLevel", levelClass).invoke(root, off);
            }
        } catch (Throwable ignored) {
            // best effort only
        }
    }

    // ------------------------------------------------------------------ //
    //  Fuzzing                                                             //
    // ------------------------------------------------------------------ //

    /** One fuzz iteration for IdRepoServiceImpl.updateIdentity. */
    public static void fuzzUpdate(byte[] input) {
        int sep = indexOf(input, (byte) 0);
        byte[] requestBytes = sep < 0 ? input : Arrays.copyOfRange(input, 0, sep);
        byte[] storedBytes = sep < 0 ? defaultStored : Arrays.copyOfRange(input, sep + 1, input.length);

        Map<String, Object> identity = parseObject(requestBytes);
        JsonNode before = parseObjectNode(storedBytes);
        if (identity == null || before == null) {
            // Not JSON objects. The controller's validator rejects a
            // non-object identity before the service, and the database only
            // ever holds objects the service itself wrote.
            return;
        }
        // The service may modify the map it is given, so copy the key names.
        Set<String> requestKeys = new HashSet<>(identity.keySet());

        Uin result;
        try {
            result = applyUpdate(identity, storedBytes);
        } catch (IdRepoAppException e) {
            return; // intended business error
        } catch (RuntimeException e) {
            if (e instanceof IdRepoAppUncheckedException) {
                return; // intended business error
            }
            throw e; // anything else is a finding, with its original stack trace
        }
        checkProperties(before, requestKeys, result);
    }

    private static Uin applyUpdate(Map<String, Object> identity, byte[] storedBytes) throws IdRepoAppException {
        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
        currentStored = new Uin("uinRefId", "encryptedUin", "1_hash", storedBytes, "dataHash", REG_ID,
                "ACTIVATED", "fuzz", now, "fuzz", now, false, null, new ArrayList<>(), new ArrayList<>());

        RequestDTO body = new RequestDTO();
        body.setRegistrationId(REG_ID);
        body.setIdentity(identity);
        IdRequestDTO request = new IdRequestDTO();
        request.setRequest(body);
        return service.updateIdentity(request, UIN);
    }

    private static Map<String, Object> parseObject(byte[] bytes) {
        try {
            Object value = MAPPER.readValue(bytes, Object.class);
            if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) value;
                return map;
            }
        } catch (IOException e) {
            // not JSON
        }
        return null;
    }

    private static JsonNode parseObjectNode(byte[] bytes) {
        try {
            JsonNode node = MAPPER.readTree(bytes);
            return node != null && node.isObject() ? node : null;
        } catch (IOException e) {
            return null;
        }
    }

    private static int indexOf(byte[] array, byte value) {
        for (int i = 0; i < array.length; i++) {
            if (array[i] == value) {
                return i;
            }
        }
        return -1;
    }

    // ------------------------------------------------------------------ //
    //  Property oracle                                                     //
    // ------------------------------------------------------------------ //

    /**
     * Checks a SUCCESSFUL update. The update logic builds JsonPath
     * expressions out of key names taken from the request, splitting on dots
     * and rewriting brackets, so a crafted key can in principle make it write
     * somewhere other than where the request pointed. These properties catch
     * that as data corruption, without relying on a crash:
     *
     *   1. the stored record is still a valid JSON object;
     *   2. the stored hash matches the stored data;
     *   3. non-interference: a top-level attribute the request did not name
     *      is unchanged, and no new top-level attribute appears that the
     *      request did not name. "verifiedAttributes" is exempt because the
     *      service manages it itself.
     */
    private static void checkProperties(JsonNode before, Set<String> requestKeys, Uin result) {
        byte[] afterBytes = result.getUinData();
        JsonNode after;
        try {
            after = MAPPER.readTree(afterBytes);
        } catch (IOException e) {
            throw new AssertionError("Stored identity after a successful update is not valid JSON: "
                    + e.getMessage(), e);
        }
        if (after == null || !after.isObject()) {
            throw new AssertionError("Stored identity after a successful update is not a JSON object");
        }
        if (!SECURITY.hash(afterBytes).equals(result.getUinDataHash())) {
            throw new AssertionError("Stored data hash does not match the stored data after an update");
        }

        Iterator<String> names = before.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (requestKeys.contains(name) || VERIFIED_ATTRIBUTES.equals(name)) {
                continue;
            }
            JsonNode now = after.get(name);
            if (now == null || !now.equals(before.get(name))) {
                throw new AssertionError("Attribute '" + name + "' was changed although the request did not "
                        + "name it. before=" + abbreviate(before.get(name)) + " after=" + abbreviate(now));
            }
        }
        names = after.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (!before.has(name) && !requestKeys.contains(name) && !VERIFIED_ATTRIBUTES.equals(name)) {
                throw new AssertionError("Attribute '" + name + "' was created although the request did not "
                        + "name it. value=" + abbreviate(after.get(name)));
            }
        }
    }

    private static String abbreviate(JsonNode node) {
        String text = String.valueOf(node);
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }

    // ------------------------------------------------------------------ //
    //  Start-up self-check                                                 //
    // ------------------------------------------------------------------ //

    /**
     * Applies one known-valid update through the freshly wired service and
     * requires it to reach the end (uinRepo.save) and satisfy the property
     * checks. If the wiring is wrong (a field missing, a config value not
     * set), a harness would otherwise "run" while failing on every input,
     * which looks like a healthy fuzzer that finds nothing.
     */
    private static void selfCheck() {
        Map<String, Object> identity = parseObject("{\"phone\":\"1234567890\"}".getBytes(StandardCharsets.UTF_8));
        Set<String> requestKeys = new HashSet<>(identity.keySet());
        JsonNode before = parseObjectNode(defaultStored);
        long savesBefore = saveCalls;

        Uin result;
        try {
            result = applyUpdate(identity, defaultStored);
        } catch (Exception e) {
            throw new IllegalStateException("Service harness self-check failed: a known-valid update threw "
                    + e + " -- the harness wiring is wrong, this is not a finding.", e);
        }
        if (saveCalls == savesBefore) {
            throw new IllegalStateException("Service harness self-check failed: a known-valid update did not "
                    + "reach uinRepo.save -- the harness wiring is wrong, this is not a finding.");
        }
        try {
            checkProperties(before, requestKeys, result);
        } catch (AssertionError e) {
            throw new IllegalStateException("Service harness self-check failed: a property check failed on a "
                    + "known-valid update (" + e.getMessage() + "). Either an invariant in checkProperties is "
                    + "wrong, or MOSIP has a bug. Resolve that before fuzzing.", e);
        }
    }
}
