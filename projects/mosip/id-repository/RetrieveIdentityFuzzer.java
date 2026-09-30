import java.util.Map;
import java.util.Optional;

import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.springframework.test.util.ReflectionTestUtils;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.identity.repository.UinRepo;
import io.mosip.idrepository.identity.service.impl.IdRepoServiceImpl;

/**
 * Module under test: id-repository-identity-service
 * Target: IdRepoServiceImpl.retrieveIdentity(String, IdType, String, Map)
 *
 * Mocking needed: retrieveIdentity() calls uinRepo.findByUinHash(), which
 * would otherwise require a live Postgres connection. UinRepo is a plain
 * Spring Data interface (extends JpaRepository<Uin, String>), so Mockito
 * can fake it entirely -- no schema, no container, no DB engine at all.
 *
 * The mock is wired into the private @Autowired field via
 * ReflectionTestUtils.setField -- the same utility MOSIP's own
 * IdRequestValidatorTest already uses -- because there's no Spring context
 * here to do the injection for us; fuzzerTestOneInput is a bare static
 * method, not something JUnit drives.
 *
 * Gotcha to know about: IdRepoServiceImpl has several other @Autowired
 * repository fields (uinDocHRepo, uinBioHRepo, credRequestRepo, etc.).
 * retrieveIdentity() itself doesn't reach any of them, so this harness is
 * safe as written -- but if you extend this to fuzz addIdentity() or
 * updateIdentity() instead, every field those methods actually touch needs
 * the same mock-and-inject treatment, or you'll get NullPointerExceptions
 * that are harness bugs, not real findings.
 */
public class RetrieveIdentityFuzzer {

    private static final IdRepoServiceImpl SERVICE = new IdRepoServiceImpl();

    static {
        UinRepo mockUinRepo = mock(UinRepo.class);
        when(mockUinRepo.findByUinHash(anyString())).thenReturn(Optional.empty());
        ReflectionTestUtils.setField(SERVICE, "uinRepo", mockUinRepo);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String uinHash = data.consumeRemainingAsString();
        try {
            SERVICE.retrieveIdentity(uinHash, null, null, Map.of());
        } catch (IdRepoAppException e) {
            // Expected: NO_RECORD_FOUND, since the mock always reports nothing present.
        }
    }
}
