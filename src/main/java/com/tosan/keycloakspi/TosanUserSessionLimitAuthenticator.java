package com.tosan.keycloakspi;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.HostUtils;
import org.keycloak.models.*;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.utils.LockObjectsForModification;
import org.keycloak.utils.StringUtil;

import java.util.*;
import java.util.stream.Collectors;

public class TosanUserSessionLimitAuthenticator implements Authenticator  {
    private static Logger logger = Logger.getLogger(TosanUserSessionLimitAuthenticator.class);
    private static final String BRANCH_PARAMETER ="branch";
    private static String realmEventDetailsTemplate = "Realm session limit exceeded. Realm: %s, Realm limit: %s. Session count: %s, User id: %s";
    private static String clientEventDetailsTemplate = "Client session limit exceeded. Realm: %s, Client limit: %s. Session count: %s, User id: %s";
    protected KeycloakSession session;
    String behavior;
    String decision;
    public TosanUserSessionLimitAuthenticator(KeycloakSession session) {
        this.session = session;
    }
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) {
            throw new AuthenticationFlowException("No configuration found of 'Tosan user Session Count Limiter' authenticator. Please make sure to configure this authenticator in your authentication flow in the realm '" + context.getRealm().getName() + "'!", AuthenticationFlowError.INTERNAL_ERROR);
        } else {
            Map<String, String> config = authenticatorConfig.getConfig();
            this.behavior = config.get("behavior");
            this.decision = config.get("decision");
            int userRealmLimit = this.getIntConfigProperty("userRealmLimit", config);
            int userClientLimit = this.getIntConfigProperty("userClientLimit", config);
            if (context.getRealm() != null && context.getUser() != null) {
                logger.info("Limitation operation is made based on "+ decision);
                List<UserSessionModel> userSessionsForRealm = (List)LockObjectsForModification.lockUserSessionsForModification(this.session, () -> {
                    return this.session.sessions().getUserSessionsStream(context.getRealm(), context.getUser()).collect(Collectors.toList());
                });
                if(decision.equals("User & IP")) {
                    userSessionsForRealm= filterOnIp(context, userSessionsForRealm);
                }
                int userSessionCountForRealm = userSessionsForRealm.size();

                ClientModel currentClient = context.getAuthenticationSession().getClient();
                logger.debugf("session-limiter's current keycloak clientId: %s", currentClient.getClientId());
                List<UserSessionModel> userSessionsForClient = this.getUserSessionsForClientIfEnabled(userSessionsForRealm, currentClient, userClientLimit);
                if(decision.equals("User & IP")) {
                    userSessionsForClient= filterOnIp(context, userSessionsForClient);
                }
                int userSessionCountForClient = userSessionsForClient.size();
                logger.debugf("session-limiter's configured realm session limit: %s", userRealmLimit);
                logger.debugf("session-limiter's configured client session limit: %s", userClientLimit);
                logger.debugf("session-limiter's count of total user sessions for the entire realm (could be apps other than web apps): %s", userSessionCountForRealm);
                logger.debugf("session-limiter's count of total user sessions for this keycloak client: %s", userSessionCountForClient);
                String eventDetails;
                if (this.exceedsLimit((long)userSessionCountForRealm, (long)userRealmLimit)) {
                    logger.infof("Too many session in this realm for the current user. Session count: %s", userSessionCountForRealm);
                    eventDetails = String.format(realmEventDetailsTemplate, context.getRealm().getName(), userRealmLimit, userSessionCountForRealm, context.getUser().getId());
                    this.handleLimitExceeded(context, userSessionsForRealm, eventDetails, (long)userRealmLimit);
                } else if (this.exceedsLimit((long)userSessionCountForClient, (long)userClientLimit)) {
                    logger.infof("Too many sessions related to the current client for this user. Session count: %s", userSessionCountForRealm);
                    eventDetails = String.format(clientEventDetailsTemplate, context.getRealm().getName(), userClientLimit, userSessionCountForClient, context.getUser().getId());
                    this.handleLimitExceeded(context, userSessionsForClient, eventDetails, (long)userClientLimit);
                } else {
                    context.success();
                }
            } else {
                context.success();
            }

        }
    }

    private static List<UserSessionModel> filterOnIp(AuthenticationFlowContext context, List<UserSessionModel> userSessionsForRealm) {
        if(!userSessionsForRealm.isEmpty()) {
            return userSessionsForRealm.stream()
                    .filter( session-> session.getIpAddress().equals(context.getConnection().getRemoteAddr()))
                    .collect(Collectors.toList());
        }
        return userSessionsForRealm;
    }

    private boolean exceedsLimit(long count, long limit) {
        if (limit <= 0L) {
            return false;
        } else {
            return this.getNumberOfSessionsThatNeedToBeLoggedOut(count, limit) > 0L;
        }
    }

    private long getNumberOfSessionsThatNeedToBeLoggedOut(long count, long limit) {
        return count - (limit - 1L);
    }

    private int getIntConfigProperty(String key, Map<String, String> config) {
        String value = (String)config.get(key);
        return StringUtil.isBlank(value) ? -1 : Integer.parseInt(value);
    }

    private List<UserSessionModel> getUserSessionsForClientIfEnabled(List<UserSessionModel> userSessionsForRealm, ClientModel currentClient, int userClientLimit) {
        if (userClientLimit <= 0) {
            return Collections.EMPTY_LIST;
        } else {
            logger.debugf("total user sessions for this keycloak client will not be counted. Will be logged as 0 (zero)", new Object[0]);
            List<UserSessionModel> userSessionsForClient = (List)userSessionsForRealm.stream().filter((session) -> {
                return session.getAuthenticatedClientSessionByClient(currentClient.getId()) != null;
            }).collect(Collectors.toList());
            return userSessionsForClient;
        }
    }
    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("TosanUserSessionLimitAuthenticator action is called");
    }
    @Override
    public boolean requiresUser() {
        return false;
    }
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }
    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("TosanUserSessionLimitAuthenticator setRequiredActions is called");
    }
    @Override
    public void close() {
        logger.debug("TosanUserSessionLimitAuthenticator close is called");
    }

    private void handleLimitExceeded(AuthenticationFlowContext context, List<UserSessionModel> userSessions, String eventDetails, long limit) {
        switch (this.behavior) {
            case "Deny new session":
                logger.info("Denying new session");
                String errorMessage = (String) Optional.ofNullable(context.getAuthenticatorConfig()).map(AuthenticatorConfigModel::getConfig).map((f) -> {
                    return (String)f.get("errorMessage");
                }).orElse("sessionLimitExceeded");
                context.getEvent().error("generic_authentication_error");
                Response challenge = null;
                if (context.getFlowPath() == null) {
                    OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation("generic_authentication_error", errorMessage);
                    challenge = Response.status(Response.Status.UNAUTHORIZED.getStatusCode()).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
                } else {
                    challenge = context.form().setError(errorMessage, new Object[0]).createErrorPage(Response.Status.FORBIDDEN);
                }

                context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR, challenge, eventDetails, errorMessage);
                break;
            case "Terminate oldest session":
                logger.info("Terminating oldest session");
                this.logoutOldestSessions(userSessions, limit);
                context.success();
        }

    }

    private void logoutOldestSessions(List<UserSessionModel> userSessions, long limit) {
        long numberOfSessionsThatNeedToBeLoggedOut = this.getNumberOfSessionsThatNeedToBeLoggedOut((long)userSessions.size(), limit);
        if (numberOfSessionsThatNeedToBeLoggedOut == 1L) {
            logger.info("Logging out oldest session");
        } else {
            logger.infof("Logging out oldest %s sessions", numberOfSessionsThatNeedToBeLoggedOut);
        }

        userSessions.stream().sorted(Comparator.comparingInt(UserSessionModel::getLastSessionRefresh)).limit(numberOfSessionsThatNeedToBeLoggedOut).forEach((userSession) -> {
            AuthenticationManager.backchannelLogout(this.session, userSession, true);
        });
    }
}
