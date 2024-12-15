package com.tosan.keycloakspi;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.List;

public class TosanUserSessionLimitAuthenticatorFactory implements AuthenticatorFactory {
    private final Logger log =Logger.getLogger(TosanUserSessionLimitAuthenticatorFactory.class);

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES;

    public TosanUserSessionLimitAuthenticatorFactory() {
    }

    public String getDisplayType() {
        return "Tosan user session count limiter";
    }

    public String getReferenceCategory() {
        return null;
    }

    public boolean isConfigurable() {
        return true;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public String getHelpText() {
        return "Configures how many concurrent sessions a single user with its assigned branch is allowed to create for this realm and/or client";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty userRealmLimit = new ProviderConfigProperty();
        userRealmLimit.setName("userRealmLimit");
        userRealmLimit.setLabel("Maximum concurrent sessions for each user within this realm.");
        userRealmLimit.setHelpText("Provide a zero or negative value to disable this limit.");
        userRealmLimit.setType("String");
        userRealmLimit.setDefaultValue("3");
        ProviderConfigProperty userClientLimit = new ProviderConfigProperty();
        userClientLimit.setName("userClientLimit");
        userClientLimit.setLabel("Maximum concurrent sessions for each user per keycloak client.");
        userClientLimit.setHelpText("Provide a zero or negative value to disable this limit. In case a limit for the realm is enabled, specify this value below the total realm limit.");
        userClientLimit.setType("String");
        userClientLimit.setDefaultValue("0");
        ProviderConfigProperty decisionProperty = new ProviderConfigProperty();
        decisionProperty.setName("decision");
        decisionProperty.setLabel("decide to limit session based on");
        decisionProperty.setType("List");
        decisionProperty.setDefaultValue("User");
        decisionProperty.setOptions(Arrays.asList("User", "User & IP"));
        ProviderConfigProperty behaviourProperty = new ProviderConfigProperty();
        behaviourProperty.setName("behavior");
        behaviourProperty.setLabel("Behavior when user session limit is exceeded");
        behaviourProperty.setType("List");
        behaviourProperty.setDefaultValue("Deny new session");
        behaviourProperty.setOptions(Arrays.asList("Deny new session", "Terminate oldest session"));
        ProviderConfigProperty customErrorMessage = new ProviderConfigProperty();
        customErrorMessage.setName("errorMessage");
        customErrorMessage.setLabel("Optional custom error message");
        customErrorMessage.setHelpText("If left empty a default error message is shown");
        customErrorMessage.setType("String");
        return Arrays.asList(userRealmLimit, userClientLimit,decisionProperty, behaviourProperty, customErrorMessage);
    }

    public Authenticator create(KeycloakSession keycloakSession) {
        return new TosanUserSessionLimitAuthenticator(keycloakSession);
    }

    public void init(Config.Scope scope) {
        log.debug("TosanUserSessionLimitAuthenticatorFactory init is called");
    }

    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        log.debug("TosanUserSessionLimitAuthenticatorFactory postInit is called");
    }

    public void close() {
        log.debug("TosanUserSessionLimitAuthenticatorFactory close is called");
    }

    public String getId() {
        return "tosan-user-session-limits";
    }

    static {
        REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED};
    }
}
