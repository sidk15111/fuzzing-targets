import static org.mockito.Mockito.RETURNS_DEFAULTS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.ErrorResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.idrepository.core.dto.IdentityMapping;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.exception.IdRepoAppUncheckedException;
import io.mosip.idrepository.core.exception.IdRepoExceptionHandler;
import io.mosip.idrepository.core.helper.AuditHelper;
import io.mosip.idrepository.core.spi.IdRepoService;
import io.mosip.idrepository.core.util.EnvUtil;
import io.mosip.idrepository.identity.controller.IdRepoController;
import io.mosip.idrepository.identity.helper.IdRepoServiceHelper;
import io.mosip.idrepository.identity.validator.IdRequestValidator;
import io.mosip.kernel.core.idobjectvalidator.spi.IdObjectValidator;
import io.mosip.kernel.core.idvalidator.spi.UinValidator;

/**
 * Shared wiring for the controller-level harnesses
 * (IdRepoControllerAddIdentityFuzzer, IdRepoControllerUpdateIdentityFuzzer).
 *
 * NOT a fuzz target: the name deliberately does not end in "Fuzzer", so
 * build.sh does not wrap it and project.yaml does not list it.
 *
 * What is REAL in the harness (this is the code being fuzzed):
 *   - Spring MVC request handling via standalone MockMvc (no application
 *     context): Jackson deserialization into IdRequestDTO, @InitBinder,
 *     @Validated, argument resolution
 *   - IdRequestValidator (validate / validateRequest / validateDocuments)
 *   - IdRepoServiceHelper.convertToMap and the identity-mapping lookup
 *   - IdRepoController (addIdentity / updateIdentity, getUin via JsonPath)
 *   - IdRepoExceptionHandler, the production @ControllerAdvice
 *
 * What is FAKED (I/O edges and things we are deliberately not testing):
 *   - IdRepoService (the layer behind the controller): a counting stub
 *   - AuditHelper: no-op stub
 *   - UinValidator: always accepts, so fuzzed requests are not rejected by a
 *     checksum before reaching the controller body
 *   - IdObjectValidator (kernel JSON-schema validation): always accepts
 *   - IdRepoServiceHelper.getSchema: returns "{}" instead of a REST call to
 *     the syncdata service (the null-schema-version check stays real)
 *
 * Why an oracle is needed: IdRepoExceptionHandler catches EVERY exception
 * and converts it to an HTTP 200 response, so an unexpected
 * NullPointerException or ClassCastException inside the request path would
 * otherwise be invisible to Jazzer. fuzz() therefore reads the exception the
 * handler resolved (MvcResult#getResolvedException) and rethrows it unless
 * it is one of the exception types the code raises on purpose.
 */
public final class IdRepoFuzzSupport {

    private static final String CREATE_ID = "mosip.id.create";
    private static final String UPDATE_ID = "mosip.id.update";

    // Same keys/values as the "id" bean in application.properties
    // (mosip.idrepo.identity.id.create/read/update).
    private static final Map<String, String> ID_MAP = Map.of(
            "create", CREATE_ID,
            "read", "mosip.id.read",
            "update", UPDATE_ID);

    // Counts calls that reached the (stubbed) service layer. Used only by the
    // start-up self-check to prove the wiring lets a valid request through.
    private static final AtomicLong SERVICE_CALLS = new AtomicLong();

    // Spring's own builder: same defaults as Spring Boot's auto-configured
    // mapper (unknown properties ignored, java.time and Jdk8 modules
    // registered when present on the classpath).
    private static final ObjectMapper MAPPER = Jackson2ObjectMapperBuilder.json().build();

    private IdRepoFuzzSupport() {
    }

    // ------------------------------------------------------------------ //
    //  Wiring                                                              //
    // ------------------------------------------------------------------ //

    /**
     * Builds the standalone MockMvc once per process (call from a static
     * initializer), then runs the self-check for the given endpoint.
     */
    public static MockMvc newMockMvc(boolean update) {
        silenceLogging();
        configureEnvUtil();

        IdRequestValidator validator = buildValidator();

        IdRepoController controller = new IdRepoController();
        ReflectionTestUtils.setField(controller, "id", ID_MAP);
        ReflectionTestUtils.setField(controller, "mapper", MAPPER);
        ReflectionTestUtils.setField(controller, "validator", validator);
        ReflectionTestUtils.setField(controller, "auditHelper",
                mock(AuditHelper.class, withSettings().stubOnly()));
        ReflectionTestUtils.setField(controller, "idRepoService", buildCountingService());

        IdRepoExceptionHandler handler = new IdRepoExceptionHandler();
        ReflectionTestUtils.setField(handler, "id", ID_MAP);

        MockMvc mvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(handler)
                .setMessageConverters(new MappingJackson2HttpMessageConverter(MAPPER))
                .build();

        selfCheck(mvc, update);
        return mvc;
    }

    // EnvUtil holds static configuration that Spring normally fills from
    // properties. Only the values this request path reads are set.
    private static void configureEnvUtil() {
        EnvUtil.setDateTimeAdjustment(0L);
        EnvUtil.setVersionPattern("^v\\d+(\\.\\d+)?$");
        EnvUtil.setUinJsonPath("identity.UIN");
        EnvUtil.setAppVersion("1.0");
    }

    @SuppressWarnings("unchecked")
    private static IdRequestValidator buildValidator() {
        FuzzServiceHelper helper = new FuzzServiceHelper();
        ReflectionTestUtils.setField(helper, "mapper", MAPPER);
        ReflectionTestUtils.setField(helper, "identityMapping", loadIdentityMapping());

        UinValidator<String> uinValidator = mock(UinValidator.class, withSettings().stubOnly());
        when(uinValidator.validateId(org.mockito.ArgumentMatchers.any())).thenReturn(true);

        IdRequestValidator validator = new IdRequestValidator();
        ReflectionTestUtils.setField(validator, "id", ID_MAP);
        // requesttime must be within +/- this many seconds of "now". Real
        // default is 60. Seeds are static files with a fixed timestamp, so
        // widen it (about 63 years) or every seed would be rejected at the
        // first check and the fuzzer would never reach the interesting code.
        ReflectionTestUtils.setField(validator, "maxRequestTimeDeviationSeconds", 2_000_000_000);
        // application.properties: mosip.idrepo.identity.uin-status=BLOCKED,DEACTIVATED
        ReflectionTestUtils.setField(validator, "uinStatus", List.of("BLOCKED", "DEACTIVATED"));
        ReflectionTestUtils.setField(validator, "newRegistrationFields",
                new ArrayList<>(List.of("IDSchemaVersion", "UIN")));
        ReflectionTestUtils.setField(validator, "updateUinFields",
                new ArrayList<>(List.of("IDSchemaVersion", "UIN")));
        ReflectionTestUtils.setField(validator, "allowedAuthTypes", "otp,demo,bio");
        ReflectionTestUtils.setField(validator, "idObjectValidator",
                mock(IdObjectValidator.class, withSettings().stubOnly()));
        ReflectionTestUtils.setField(validator, "uinValidator", uinValidator);
        ReflectionTestUtils.setField(validator, "idRepoServiceHelper", helper);
        return validator;
    }

    // A raw IdRepoService mock whose only behaviour is "count the call and
    // return the type's default (null)". stubOnly() matters: normal Mockito
    // mocks record every invocation for verify(), which grows the heap
    // without bound over millions of fuzz iterations.
    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static Object buildCountingService() {
        return mock(IdRepoService.class, withSettings().stubOnly().defaultAnswer(invocation -> {
            SERVICE_CALLS.incrementAndGet();
            return RETURNS_DEFAULTS.answer(invocation);
        }));
    }

    private static IdentityMapping loadIdentityMapping() {
        try (InputStream in = IdRepoFuzzSupport.class.getResourceAsStream("/identity-mapping.json")) {
            if (in == null) {
                throw new IllegalStateException("identity-mapping.json is not on the classpath. "
                        + "It is copied from fixtures/ into $OUT by build.sh.");
            }
            return MAPPER.readValue(in, IdentityMapping.class);
        } catch (IOException e) {
            throw new IllegalStateException("Could not parse identity-mapping.json", e);
        }
    }

    // The real getSchema() fetches the schema over REST from the syncdata
    // service. Keep its real null/"null" check (it throws
    // IdRepoAppUncheckedException before touching REST), but for every
    // other version return an empty schema, since IdObjectValidator is
    // stubbed and ignores it.
    static final class FuzzServiceHelper extends IdRepoServiceHelper {
        @Override
        public String getSchema(String schemaVersion) {
            if (Objects.isNull(schemaVersion) || schemaVersion.contentEquals("null")) {
                return super.getSchema(schemaVersion);
            }
            return "{}";
        }
    }

    // MOSIP's kernel logger writes through slf4j. The validator and the
    // exception handler log on almost every rejected request, which would
    // dominate run time and flood the bot's disk. Done reflectively so the
    // harness still compiles and runs if the backend is not logback.
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

    /** Sends the fuzz bytes as the JSON body and applies the crash oracle. */
    public static void fuzz(MockMvc mvc, boolean update, byte[] body) {
        MvcResult result;
        try {
            result = send(mvc, update, body);
        } catch (Exception e) {
            // Escaped even the exception handler. Spring wraps the real
            // cause in a ServletException, so report the cause.
            report(e.getCause() != null ? e.getCause() : e);
            return;
        }
        Exception resolved = result.getResolvedException();
        if (resolved != null) {
            report(resolved);
        }
    }

    /**
     * Decides what to do with one exception raised in the request path:
     * ignore it if it is intended behaviour, ignore it (and count it) if it
     * is a known, already-reported bug, otherwise rethrow it so Jazzer
     * records a finding.
     */
    private static void report(Throwable t) {
        if (isExpected(t)) {
            return;
        }
        String knownIssue = matchKnownIssue(t);
        if (knownIssue != null) {
            noteKnownIssue(knownIssue);
            return;
        }
        throw sneakyThrow(t);
    }

    private static MvcResult send(MockMvc mvc, boolean update, byte[] body) throws Exception {
        MockHttpServletRequestBuilder request = update
                ? MockMvcRequestBuilders.patch("/")
                : MockMvcRequestBuilders.post("/");
        return mvc.perform(request.contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    /**
     * Exceptions the code raises on purpose, i.e. correct handling of bad
     * input, not bugs:
     *   - IdRepoAppException (incl. IdRepoUnknownException) and
     *     IdRepoAppUncheckedException: MOSIP's own error types
     *   - HttpMessageNotReadableException: malformed JSON / wrong field types
     *   - ErrorResponse: Spring MVC client errors (unsupported media type,
     *     method argument not valid, ...)
     * Anything else (NullPointerException, ClassCastException,
     * IndexOutOfBoundsException, ...) is reported as a finding.
     */
    private static boolean isExpected(Throwable t) {
        return t instanceof IdRepoAppException
                || t instanceof IdRepoAppUncheckedException
                || t instanceof HttpMessageNotReadableException
                || t instanceof ErrorResponse;
    }

    // ------------------------------------------------------------------ //
    //  Known issues                                                        //
    // ------------------------------------------------------------------ //

    // A bug that has already been triaged and reported upstream, but is still
    // present in MOSIP master. It sits at the front door of every request, so
    // left unfiltered it ends every fuzzing session within minutes and hides
    // anything deeper. While it is listed here the fuzzer skips it and keeps
    // going. Add an entry ONLY after the bug has been reported, and delete the
    // entry once upstream fixes it, so that a regression is caught again.
    //
    // Entry "validator-null-request":
    //   IdRequestValidator.validate() calls request.getRequest().<something>
    //   without checking that "request" is present, so a body with no
    //   "request" object throws NullPointerException (lines 180/183/189 in
    //   master at the time of writing). Matched on exception type, the
    //   throwing method, and the null being the result of getRequest() --
    //   NOT on line numbers, which drift whenever upstream edits the file.
    private static final String KNOWN_NULL_REQUEST = "validator-null-request";

    private static long knownIssueHits;

    /** Returns the id of the known issue this exception is, or null. */
    private static String matchKnownIssue(Throwable t) {
        if (t instanceof NullPointerException) {
            StackTraceElement[] stack = t.getStackTrace();
            // Needs a stack trace and a message. The JVM's "fast throw"
            // optimization can strip both from a NullPointerException that
            // has been thrown many times; the wrapper script disables it
            // (-XX:-OmitStackTraceInFastThrow). If it ever sneaks back in,
            // the exception is deliberately NOT matched and shows up as an
            // un-triageable finding, which is the loud failure we want.
            if (stack.length > 0 && t.getMessage() != null
                    && "io.mosip.idrepository.identity.validator.IdRequestValidator"
                            .equals(stack[0].getClassName())
                    && "validate".equals(stack[0].getMethodName())
                    && t.getMessage().contains("IdRequestDTO.getRequest()")) {
                return KNOWN_NULL_REQUEST;
            }
        }
        return null;
    }

    private static void noteKnownIssue(String id) {
        if (knownIssueHits++ == 0) {
            System.err.println("IdRepoFuzzSupport: skipping known issue '" + id
                    + "' (see README, Known issues). Further hits are counted silently.");
        }
    }

    // Rethrows the ORIGINAL exception (class and stack trace intact) without
    // declaring it, so Jazzer's report and de-duplication point at the real
    // line in MOSIP's code rather than at a wrapper.
    private static RuntimeException sneakyThrow(Throwable t) {
        IdRepoFuzzSupport.<RuntimeException>doSneakyThrow(t);
        throw new AssertionError("unreachable");
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void doSneakyThrow(Throwable t) throws E {
        throw (E) t;
    }

    // ------------------------------------------------------------------ //
    //  Start-up self-check                                                 //
    // ------------------------------------------------------------------ //

    /**
     * Sends one known-valid request through the freshly built MockMvc and
     * requires that it reaches the stubbed service with no exception. If the
     * wiring above is wrong (a field not injected, a config value missing),
     * a harness would otherwise "run" while rejecting every input at the
     * first check, which looks like a healthy fuzzer producing no findings.
     * Failing here makes that mistake loud, and check_build catches it.
     */
    private static void selfCheck(MockMvc mvc, boolean update) {
        String id = update ? UPDATE_ID : CREATE_ID;
        String status = update ? "BLOCKED" : "ACTIVATED";
        String body = "{\"id\":\"" + id + "\",\"version\":\"v1\",\"requesttime\":\""
                + LocalDateTime.now(ZoneOffset.UTC) + "\",\"request\":{"
                + "\"registrationId\":\"10001100010000620200101000000\","
                + "\"status\":\"" + status + "\","
                + "\"identity\":{\"IDSchemaVersion\":0.1,\"UIN\":\"2419762130\","
                + "\"fullName\":[{\"language\":\"eng\",\"value\":\"name\"}]}}}";

        long before = SERVICE_CALLS.get();
        MvcResult result;
        try {
            result = send(mvc, update, body.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Harness self-check failed: a known-valid request threw " + e, e);
        }
        Exception resolved = result.getResolvedException();
        if (resolved != null) {
            throw new IllegalStateException(
                    "Harness self-check failed: a known-valid request raised " + resolved
                            + " -- the harness wiring is wrong, this is not a finding.",
                    resolved);
        }
        if (SERVICE_CALLS.get() == before) {
            throw new IllegalStateException(
                    "Harness self-check failed: a known-valid request did not reach the stubbed service. "
                            + "Response was: "
                            + new String(result.getResponse().getContentAsByteArray(), StandardCharsets.UTF_8)
                            + " -- the harness wiring is wrong, this is not a finding.");
        }
    }
}
