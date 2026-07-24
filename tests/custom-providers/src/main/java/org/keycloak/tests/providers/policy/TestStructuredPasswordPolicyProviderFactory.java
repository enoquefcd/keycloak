package org.keycloak.tests.providers.policy;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.component.ComponentFactory;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.policy.PolicyError;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Password policy factory backed by components, the way {@code UserStorageProviderFactory} works:
 * it implements {@link ComponentFactory}, declares its parameters through
 * {@code getConfigProperties()}, and receives them individually through the {@link ComponentModel}.
 * Used to exercise the structured password policy configuration proof of concept.
 */
public class TestStructuredPasswordPolicyProviderFactory
        implements PasswordPolicyProviderFactory, ComponentFactory<PasswordPolicyProvider, PasswordPolicyProvider> {

    public static final String ID = "test-structured-policy";

    public static final String MIN_LENGTH = "minLength";
    public static final String REQUIRE_PREFIX = "requirePrefix";
    public static final String CASE_SENSITIVE = "caseSensitive";

    public static final int DEFAULT_MIN_LENGTH = 8;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        // legacy path: the policy added as a plain policy token runs with the declared defaults
        return new TestStructuredPasswordPolicyProvider(DEFAULT_MIN_LENGTH, "", false);
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session, ComponentModel model) {
        return new TestStructuredPasswordPolicyProvider(
                model.get(MIN_LENGTH, DEFAULT_MIN_LENGTH),
                model.get(REQUIRE_PREFIX, ""),
                model.get(CASE_SENSITIVE, false));
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        int minLength;
        try {
            minLength = model.get(MIN_LENGTH, DEFAULT_MIN_LENGTH);
        } catch (NumberFormatException e) {
            throw new ComponentValidationException("minLength must be a number");
        }
        if (minLength < 1) {
            throw new ComponentValidationException("minLength must be 1 or greater");
        }
    }

    @Override
    public String getDisplayName() {
        return "Test Structured Policy";
    }

    @Override
    public String getConfigType() {
        return null;
    }

    @Override
    public String getDefaultConfigValue() {
        return null;
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Test policy with individually declared configuration parameters.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(MIN_LENGTH)
                .label("Minimum length")
                .helpText("Minimum number of characters.")
                .type(ProviderConfigProperty.INTEGER_TYPE)
                .defaultValue(String.valueOf(DEFAULT_MIN_LENGTH))
                .add()
                .property()
                .name(REQUIRE_PREFIX)
                .label("Required prefix")
                .helpText("The password must start with this prefix, empty for none.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("")
                .add()
                .property()
                .name(CASE_SENSITIVE)
                .label("Case sensitive")
                .helpText("Match the prefix case exactly.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()
                .build();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    private static class TestStructuredPasswordPolicyProvider implements PasswordPolicyProvider {

        private final int minLength;
        private final String requirePrefix;
        private final boolean caseSensitive;

        TestStructuredPasswordPolicyProvider(int minLength, String requirePrefix, boolean caseSensitive) {
            this.minLength = minLength;
            this.requirePrefix = requirePrefix;
            this.caseSensitive = caseSensitive;
        }

        @Override
        public PolicyError validate(RealmModel realm, UserModel user, String password) {
            return validate(user.getUsername(), password);
        }

        @Override
        public PolicyError validate(String user, String password) {
            if (password.length() < minLength) {
                return new PolicyError("invalidPasswordMinLengthMessage", minLength);
            }
            if (!requirePrefix.isEmpty()) {
                String candidate = caseSensitive ? password : password.toLowerCase();
                String prefix = caseSensitive ? requirePrefix : requirePrefix.toLowerCase();
                if (!candidate.startsWith(prefix)) {
                    return new PolicyError("invalidPasswordTestPrefixMessage", requirePrefix);
                }
            }
            return null;
        }

        @Override
        public Object parseConfig(String value) {
            return value;
        }

        @Override
        public void close() {
        }
    }
}
