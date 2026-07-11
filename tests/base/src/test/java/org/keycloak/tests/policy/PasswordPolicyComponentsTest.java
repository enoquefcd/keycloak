package org.keycloak.tests.policy;

import java.util.List;

import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.ComponentTypeRepresentation;
import org.keycloak.testframework.annotations.InjectAdminClient;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.util.ApiUtil;
import org.keycloak.tests.common.CustomProvidersServerConfig;
import org.keycloak.tests.providers.policy.TestStructuredPasswordPolicyProviderFactory;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proof of concept scenarios for password policies configured as components (structured,
 * per-parameter configuration), alongside the legacy single-string realm policy.
 */
@KeycloakIntegrationTest(config = CustomProvidersServerConfig.class)
public class PasswordPolicyComponentsTest {

    private static final String PROVIDER_TYPE = PasswordPolicyProvider.class.getName();
    private static final String PROVIDER_ID = TestStructuredPasswordPolicyProviderFactory.ID;

    @InjectRealm
    ManagedRealm managedRealm;

    @InjectAdminClient
    Keycloak adminClient;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @AfterEach
    public void cleanup() {
        managedRealm.admin().components().query(managedRealm.getId(), PROVIDER_TYPE)
                .forEach(component -> managedRealm.admin().components().component(component.getId()).remove());
        runOnServer.run(session -> {
            session.getContext().getRealm().setPasswordPolicy(PasswordPolicy.parse(session, ""));
        });
    }

    @Test
    public void structuredPolicyEnforcedViaComponent() {
        addComponent("structured", config("10", "abc", "false"));

        runOnServer.run(session -> {
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            assertEquals("invalidPasswordMinLengthMessage", policyManager.validate("jdoe", "abc4567").getMessage());
            assertEquals("invalidPasswordTestPrefixMessage", policyManager.validate("jdoe", "xbcdefghij").getMessage());
            assertNull(policyManager.validate("jdoe", "abcdefghij"));
            // case-insensitive prefix by configuration
            assertNull(policyManager.validate("jdoe", "ABCdefghij"));
        });
    }

    @Test
    public void caseSensitivePrefixEnforced() {
        addComponent("case-sensitive", config("4", "abc", "true"));

        runOnServer.run(session -> {
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            assertEquals("invalidPasswordTestPrefixMessage", policyManager.validate("jdoe", "ABCdefghij").getMessage());
            assertNull(policyManager.validate("jdoe", "abcdefghij"));
        });
    }

    @Test
    public void legacyStringPoliciesEnforcedAlongsideComponents() {
        addComponent("structured", config("4", "abc", "false"));

        runOnServer.run(session -> {
            session.getContext().getRealm().setPasswordPolicy(PasswordPolicy.parse(session, "length(12)"));
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            // satisfies the component policy but not the legacy one
            assertEquals("invalidPasswordMinLengthMessage", policyManager.validate("jdoe", "abcdefghij").getMessage());
            // satisfies both
            assertNull(policyManager.validate("jdoe", "abcdefghijkl"));
        });
    }

    @Test
    public void declaredDefaultsApplied() {
        // only the prefix is configured; minLength keeps the declared default of 8
        addComponent("defaults", config(null, "abc", null));

        runOnServer.run(session -> {
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            assertEquals("invalidPasswordMinLengthMessage", policyManager.validate("jdoe", "abc4567").getMessage());
            assertNull(policyManager.validate("jdoe", "abcdefgh"));
        });
    }

    @Test
    public void perParameterValidationOnCreateAndUpdate() {
        ComponentRepresentation rep = representation("invalid", config("0", null, null));
        try (Response response = managedRealm.admin().components().add(rep)) {
            assertEquals(400, response.getStatus());
        }

        rep = representation("invalid", config("not-a-number", null, null));
        try (Response response = managedRealm.admin().components().add(rep)) {
            assertEquals(400, response.getStatus());
        }

        // a valid component cannot be updated into an invalid state
        String id = addComponent("valid", config("8", null, null));
        ComponentRepresentation existing = managedRealm.admin().components().component(id).toRepresentation();
        existing.getConfig().putSingle(TestStructuredPasswordPolicyProviderFactory.MIN_LENGTH, "0");
        try {
            managedRealm.admin().components().component(id).update(existing);
            throw new AssertionError("Expected the update to be rejected");
        } catch (jakarta.ws.rs.BadRequestException expected) {
        }
    }

    @Test
    public void multipleInstancesEnforcedTogether() {
        addComponent("min-ten", config("10", null, null));
        addComponent("prefixed", config("1", "abc", null));

        runOnServer.run(session -> {
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            // fails the second instance
            assertEquals("invalidPasswordTestPrefixMessage", policyManager.validate("jdoe", "0123456789").getMessage());
            // fails the first instance
            assertEquals("invalidPasswordMinLengthMessage", policyManager.validate("jdoe", "abc456").getMessage());
            // satisfies both instances
            assertNull(policyManager.validate("jdoe", "abc4567890"));
        });
    }

    @Test
    public void legacyTokenOfStructuredProviderRunsWithDefaults() {
        runOnServer.run(session -> {
            session.getContext().getRealm().setPasswordPolicy(
                    PasswordPolicy.parse(session, TestStructuredPasswordPolicyProviderFactory.ID));
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            assertEquals("invalidPasswordMinLengthMessage", policyManager.validate("jdoe", "1234567").getMessage());
            assertNull(policyManager.validate("jdoe", "12345678"));
        });
    }

    @Test
    public void componentConfigEquivalentToLegacyToken() {
        // the migration acceptance criterion: length(10) and a component with minLength=10
        // accept and reject exactly the same passwords
        runOnServer.run(session -> {
            RealmModel realm = session.getContext().getRealm();
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            String[] samples = {"123456789", "1234567890", "12345678901"};

            realm.setPasswordPolicy(PasswordPolicy.parse(session, "length(10)"));
            boolean[] legacy = new boolean[samples.length];
            for (int i = 0; i < samples.length; i++) {
                legacy[i] = policyManager.validate("jdoe", samples[i]) == null;
            }
            realm.setPasswordPolicy(PasswordPolicy.parse(session, ""));

            ComponentModel model = new ComponentModel();
            model.setParentId(realm.getId());
            model.setProviderId(TestStructuredPasswordPolicyProviderFactory.ID);
            model.setProviderType(PasswordPolicyProvider.class.getName());
            model.setName("equivalence");
            model.getConfig().putSingle(TestStructuredPasswordPolicyProviderFactory.MIN_LENGTH, "10");
            ComponentModel created = realm.addComponentModel(model);

            boolean[] structured = new boolean[samples.length];
            for (int i = 0; i < samples.length; i++) {
                structured[i] = policyManager.validate("jdoe", samples[i]) == null;
            }

            realm.removeComponent(created);

            for (int i = 0; i < samples.length; i++) {
                if (legacy[i] != structured[i]) {
                    throw new AssertionError("outcome differs for sample " + samples[i]);
                }
            }
        });
    }

    @Test
    public void removingComponentStopsEnforcement() {
        String id = addComponent("removable", config("12", null, null));

        runOnServer.run(session -> {
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            assertNotNull(policyManager.validate("jdoe", "shortpass"));
        });

        managedRealm.admin().components().component(id).remove();

        runOnServer.run(session -> {
            PasswordPolicyManagerProvider policyManager = session.getProvider(PasswordPolicyManagerProvider.class);
            assertNull(policyManager.validate("jdoe", "shortpass"));
        });
    }

    @Test
    public void updatingComponentAppliesNewConfig() {
        String id = addComponent("updatable", config("4", null, null));

        runOnServer.run(session -> {
            assertNull(session.getProvider(PasswordPolicyManagerProvider.class).validate("jdoe", "12345"));
        });

        ComponentRepresentation existing = managedRealm.admin().components().component(id).toRepresentation();
        existing.getConfig().putSingle(TestStructuredPasswordPolicyProviderFactory.MIN_LENGTH, "10");
        managedRealm.admin().components().component(id).update(existing);

        runOnServer.run(session -> {
            assertEquals("invalidPasswordMinLengthMessage",
                    session.getProvider(PasswordPolicyManagerProvider.class).validate("jdoe", "12345").getMessage());
            assertNull(session.getProvider(PasswordPolicyManagerProvider.class).validate("jdoe", "1234567890"));
        });
    }

    @Test
    public void serverInfoExposesParameterMetadata() {
        List<ComponentTypeRepresentation> componentTypes = adminClient.serverInfo().getInfo()
                .getComponentTypes().get(PROVIDER_TYPE);
        assertNotNull(componentTypes);
        ComponentTypeRepresentation structured = componentTypes.stream()
                .filter(componentType -> PROVIDER_ID.equals(componentType.getId()))
                .findFirst().orElseThrow(() -> new RuntimeException("Not found component type for '" + PROVIDER_ID + "'"));
        assertEquals("Test policy with individually declared configuration parameters.", structured.getHelpText());
        assertEquals(3, structured.getProperties().size());
        assertTrue(structured.getProperties().stream()
                .anyMatch(property -> TestStructuredPasswordPolicyProviderFactory.MIN_LENGTH.equals(property.getName())));
    }

    private String addComponent(String name, MultivaluedHashMap<String, String> config) {
        ComponentRepresentation rep = representation(name, config);
        try (Response response = managedRealm.admin().components().add(rep)) {
            assertEquals(201, response.getStatus());
            return ApiUtil.getCreatedId(response);
        }
    }

    private ComponentRepresentation representation(String name, MultivaluedHashMap<String, String> config) {
        ComponentRepresentation rep = new ComponentRepresentation();
        rep.setName(name);
        rep.setParentId(managedRealm.getId());
        rep.setProviderId(PROVIDER_ID);
        rep.setProviderType(PROVIDER_TYPE);
        rep.setConfig(config);
        return rep;
    }

    private MultivaluedHashMap<String, String> config(String minLength, String requirePrefix, String caseSensitive) {
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        if (minLength != null) {
            config.putSingle(TestStructuredPasswordPolicyProviderFactory.MIN_LENGTH, minLength);
        }
        if (requirePrefix != null) {
            config.putSingle(TestStructuredPasswordPolicyProviderFactory.REQUIRE_PREFIX, requirePrefix);
        }
        if (caseSensitive != null) {
            config.putSingle(TestStructuredPasswordPolicyProviderFactory.CASE_SENSITIVE, caseSensitive);
        }
        return config;
    }
}
