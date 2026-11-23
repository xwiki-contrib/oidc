/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.oidc.auth.internal.endpoint;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.auth.internal.Endpoint;
import org.xwiki.contrib.oidc.auth.internal.InvalidAccessTokenException;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.OIDCIdTokenValidator;
import org.xwiki.contrib.oidc.auth.internal.OIDCSilentReauthentication;
import org.xwiki.contrib.oidc.auth.internal.OIDCTokenRequestHelper;
import org.xwiki.contrib.oidc.auth.internal.OIDCUserManager;
import org.xwiki.contrib.oidc.auth.internal.session.ClientHttpSessions;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderException;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.ErrorResponse;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.QueryException;
import org.xwiki.security.authentication.UserAuthenticatedEvent;
import org.xwiki.user.UserReferenceResolver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiException;

/**
 * Callback endpoint for OpenID Connect.
 * 
 * @version $Id$
 */
@Component
@Named(CallbackOIDCEndpoint.HINT)
@Singleton
public class CallbackOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "authenticator/callback";

    /**
     * The errors sent back by the provider when it cannot authenticate the user without interaction.
     */
    private static final Set<String> SILENT_AUTHENTICATION_ERRORS =
        Set.of(OIDCError.LOGIN_REQUIRED.getCode(), OIDCError.INTERACTION_REQUIRED.getCode(),
            OIDCError.CONSENT_REQUIRED.getCode(), OIDCError.ACCOUNT_SELECTION_REQUIRED.getCode());

    @Inject
    private Container container;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCManager oidc;

    @Inject
    private OIDCUserManager users;

    @Inject
    private OIDCIdTokenValidator idTokenValidator;

    @Inject
    private ObservationManager observationManager;

    @Inject
    @Named("document")
    private UserReferenceResolver<String> userResolver;

    @Inject
    private ClientHttpSessions sessions;

    @Inject
    private OIDCSilentReauthentication silentReauthentication;

    @Inject
    private Logger logger;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        this.logger.debug("OIDC callback: starting with request [{}]", httpRequest.getURL());

        // Parse the request
        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(httpRequest);

        // Make sure we still have the OpenID Connect session
        if (this.configuration.getOIDCSession(false) == null) {
            return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST,
                "There is no OpenID Connection information in the current session (anymore?)");
        }

        // Make sure the session is not modified by other callbacks or authorization starts (from other browser tabs,
        // for example) while this one is handled. Waiting is fine since the requests sent to the provider are limited
        // in time.
        Lock lock = this.configuration.getSessionLock();
        lock.lock();
        try {
            return handle(httpRequest, authorizationResponse);
        } finally {
            lock.unlock();
        }
    }

    private Response handle(HTTPRequest httpRequest, AuthorizationResponse authorizationResponse) throws Exception
    {
        // Other authorizations might have been started from the same session (from other browser tabs, for example)
        // since the one this callback answers, so get back the session as it was when this one was started
        State responseState = authorizationResponse.getState();
        Map<String, Object> authorization =
            responseState != null ? this.configuration.removePendingAuthorization(responseState.getValue()) : null;
        if (authorization != null) {
            if (isAuthenticated() && isAuthentication(authorization)) {
                // The user was authenticated by a parallel authentication in the meantime, so there is no need to go
                // further (and lose the information associated with the current authentication)
                this.logger.debug("OIDC callback: the user is already authenticated, redirect to [{}]",
                    authorization.get(OIDCClientConfiguration.PROP_INITIAL_REQUEST));

                return new RedirectResponse((URI) authorization.get(OIDCClientConfiguration.PROP_INITIAL_REQUEST));
            }

            if (!isAuthentication(authorization)) {
                // The OIDC session stored in the HTTP session holds the information of the OpenID Connect
                // authentication of the current user, which must stay untouched by the OAuth2 authorization of
                // another client configuration, so this one is handled with an OIDC session of its own
                Map<String, Object> contextOIDCSession = this.configuration.getContextOIDCSession();
                this.configuration.setContextOIDCSession(new ConcurrentHashMap<>(authorization));
                try {
                    return handleAuthorization(httpRequest, authorizationResponse);
                } finally {
                    this.configuration.setContextOIDCSession(contextOIDCSession);
                }
            }

            this.configuration.restorePendingAuthorization(authorization);
        }

        return handleAuthorization(httpRequest, authorizationResponse);
    }

    private Response handleAuthorization(HTTPRequest httpRequest, AuthorizationResponse authorizationResponse)
        throws Exception
    {
        // Validate state
        Response stateError = validateState(authorizationResponse);
        if (stateError != null) {
            return stateError;
        }

        // Deal with errors
        if (!authorizationResponse.indicatesSuccess()) {
            return handleError((AuthorizationErrorResponse) authorizationResponse);
        }

        // Get the authentication response
        // TODO: it's a bit strange that there is not a more natural way to directly parse a AuthenticationResponse
        // or convert a AuthorizationSuccessResponse
        AuthenticationSuccessResponse authenticationResponse = AuthenticationSuccessResponse.parse(httpRequest);

        // Make sure the issuer is the one we expect. The expected issuer is only known when the provider is
        // configured through its issuer URL, and not when each endpoint is configured individually, in which case
        // there is nothing to compare the issuer sent back by the provider with.
        Issuer expectedIssuer = this.configuration.getIssuer();
        if (authenticationResponse.getIssuer() != null && expectedIssuer != null
            && !authenticationResponse.getIssuer().equals(expectedIssuer)) {
            return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST, "Invalid issuer: was expecting [" + expectedIssuer
                + "] and got [" + authenticationResponse.getIssuer() + "]");
        }

        ResponseType responseType = authenticationResponse.impliedResponseType();

        this.logger.debug("Auth response: the provider sent back the response type [{}]", responseType);

        // Validate the id token, if provided
        IDTokenClaimsSet idToken = parseImplicitIdToken(authenticationResponse);
        this.logger.debug("Auth response: the provider sent back the id token [{}]", idToken);

        // Get the access token
        AccessToken accessToken = authenticationResponse.getAccessToken();
        RefreshToken refreshToken = null;

        if (accessToken != null) {
            this.logger.debug("Auth response: the provider sent back an access token of type [{}]",
                accessToken.getType());
        } else {
            this.logger.debug("Auth response: the provider did not send back an access token, authorization code "
                + "received: [{}]", authenticationResponse.getAuthorizationCode() != null);

            if (authenticationResponse.getAuthorizationCode() != null) {
                OIDCTokenResponse tokenResponse = requestTokenFromAuthenticationResponse(authenticationResponse);

                accessToken = tokenResponse.getTokens().getBearerAccessToken();
                refreshToken = tokenResponse.getTokens().getRefreshToken();
                OIDCTokenRequestHelper.logRefreshTokenExpiration(tokenResponse, this.logger);

                // Also parse and validate the id token if we don't already have it
                if (configuration.isAuthenticationConfiguration() && idToken == null) {
                    idToken = parseCodeIdToken(tokenResponse.getOIDCTokens().getIDToken());
                }
            }
        }
        // Store the access token in the session

        this.configuration.setAccessToken(accessToken, refreshToken);

        if (configuration.isAuthenticationConfiguration()) {
            // Make sure there is an id token
            if (idToken == null) {
                return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST, "No id token could be found");
            }

            authenticate(idToken, accessToken, responseType);
        }

        // If the configuration indicates to store tokens, store them
        this.configuration.storeTokens(accessToken, refreshToken);

        this.logger.debug("OIDC callback: redirect=[{}]", this.configuration.getSuccessRedirectURI());

        // Redirect to original request
        return new RedirectResponse(this.configuration.getSuccessRedirectURI());
    }

    private Response validateState(AuthorizationResponse authorizationResponse)
    {
        String sessionState = this.configuration.removeSessionState();
        if (sessionState == null) {
            return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST,
                "No state could be found in the current OpenID Connection session"
                    + " which suggest it was lost or that this callback endpoint was called directly");
        }

        State providerState = authorizationResponse.getState();
        if (providerState == null) {
            return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST,
                "Invalid state: was expecting [" + sessionState + "] and got nothing");
        } else if (!Objects.equals(providerState.getValue(), sessionState)) {
            this.logger.debug("OIDC callback: Invalid state (was expecting [{}] and got [{}])", sessionState,
                providerState);

            return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST,
                "Invalid state: was expecting [" + sessionState + "] and got [" + providerState + "]");
        }

        return null;
    }

    private Response handleError(AuthorizationErrorResponse errorResponse)
    {
        // The provider cannot authenticate the user without interaction (silent authentication): the user stays
        // unauthenticated and goes back to the initial request, and no other silent authentication is attempted until
        // the user logs in again
        if (SILENT_AUTHENTICATION_ERRORS.contains(errorResponse.getErrorObject().getCode())) {
            this.logger.debug("Impossible to authenticate without interaction, redirect to [{}]",
                this.configuration.getSuccessRedirectURI());

            this.silentReauthentication.forget();

            return new RedirectResponse(this.configuration.getSuccessRedirectURI());
        }

        // Unknown error
        return new ErrorResponse(HTTPResponse.SC_SERVER_ERROR, "Unexpected error ["
            + errorResponse.getErrorObject().getCode() + "] : " + errorResponse.getErrorObject().getDescription());
    }

    private void authenticate(IDTokenClaimsSet idToken, AccessToken accessToken, ResponseType responseType)
        throws OIDCProviderException, IOException, URISyntaxException, GeneralException, JOSEException,
        BadJOSEException, ParseException, InvalidAccessTokenException, XWikiException, QueryException
    {
        UserInfo userInfo;
        if (accessToken != null && responseType.contains(Value.CODE) && !this.configuration.isUserInfoSkipped()) {
            this.logger.debug("Requesting the userinfo from a dedicated endpoint");

            // Request the user info from a dedicated endpoint if it's a code (or hybrid) flow
            userInfo = this.users.getUserInfo();
        } else {
            this.logger.debug("Using the id token as userinfo");

            // Simulate a UserInfo based on the id token
            userInfo = new UserInfo(idToken.toJSONObject());
        }

        // Update/Create XWiki user
        SimplePrincipal principal = this.users.updateUser(userInfo);

        // Remember user in the session
        HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();
        session.setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);

        // Indicate that the user is now authenticated
        this.observationManager.notify(new UserAuthenticatedEvent(this.userResolver.resolve(principal.getName())),
            null);
        // Remember the session of that OIDC user (to be able to do back channel logout)
        this.sessions.onLogin(session, idToken.getSubject());

        // Remember the authentication beyond the session, to be able to silently restart it when the user comes back
        // after the session expired
        this.silentReauthentication.onLogin();

        this.logger.debug("OIDC callback: principal=[{}]", principal);
    }

    private boolean isAuthenticated()
    {
        HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();

        return session.getAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY) != null;
    }

    private boolean isAuthentication(Map<String, Object> authorization)
    {
        // Authorizations which are not explicitly flagged are authentications
        return !Boolean.FALSE.equals(authorization.get(OIDCClientConfiguration.PROP_IS_USED_FOR_AUTHENTICATION));
    }

    private IDTokenClaimsSet parseImplicitIdToken(AuthenticationSuccessResponse authenticationResponse)
        throws GeneralException, IOException, URISyntaxException, BadJOSEException, JOSEException, OIDCProviderException
    {
        if (authenticationResponse.getIDToken() != null) {
            // Nonce is mandatory when the id token is directly provided (implicit and hybrid flows)
            Nonce nonce = this.configuration.removeSessionNonce();
            if (nonce != null) {
                return parseImplicitIdToken(nonce, authenticationResponse.getIDToken());
            }
        }

        return null;
    }

    private IDTokenClaimsSet parseImplicitIdToken(Nonce nonce, JWT token)
        throws GeneralException, IOException, URISyntaxException, BadJOSEException, JOSEException, OIDCProviderException
    {
        // Parse and validate the id token
        IDTokenClaimsSet idToken = this.idTokenValidator.validateAuthorizationResponseIdToken(token, nonce);

        if (idToken != null) {
            verifyACR(idToken);

            storeIdToken(token, idToken);

            return idToken;
        }

        // Impossible to verify the id token, ignore it since verifying the signature is mandatory for implicit and
        // hybrid flows. We don't throw an exception here in the home that the id token will be provided later, by the
        // token endpoint.
        this.logger
            .debug("No provider available. Ignoring the ID token because it's impossible to verify the signature.");

        return null;
    }

    private IDTokenClaimsSet parseCodeIdToken(JWT token) throws GeneralException, IOException, URISyntaxException,
        BadJOSEException, JOSEException, ParseException, OIDCProviderException
    {
        // Parse and validate the id token
        IDTokenClaimsSet idToken = this.idTokenValidator.validateTokenEndpointIdToken(token);

        verifyACR(idToken);

        storeIdToken(token, idToken);

        return idToken;
    }

    private void storeIdToken(JWT token, IDTokenClaimsSet idToken)
    {
        this.logger.debug("OIDC Id Token: {}", idToken);

        // Store the original id token as sent by the provider
        this.configuration.setIdTokenJWT(token);
        // Store the id token in the session
        this.configuration.setIdToken(idToken);
    }

    private void verifyACR(IDTokenClaimsSet idToken) throws OIDCProviderException
    {
        // Check if ACR is specified and if yes, if value from config matches value returned in id token
        OIDCClaimsRequest claimsRequest = this.configuration.getClaimsRequest();
        ClaimsSetRequest idTokenClaimsRequest = claimsRequest.getIDTokenClaimsRequest();
        if (idTokenClaimsRequest != null) {
            Entry acrClaim = idTokenClaimsRequest.get("acr");
            if (acrClaim != null) {
                // ACR can take either a single 'value' or an array of 'values'
                List<String> claimsAcrValues = acrClaim.getValuesAsListOfStrings();
                String claimsAcrValue = acrClaim.getValueAsString();
                List<String> requestedAcrValues = new ArrayList<>();
                if (claimsAcrValues != null)
                    requestedAcrValues.addAll(claimsAcrValues);
                if (claimsAcrValue != null)
                    requestedAcrValues.add(claimsAcrValue);

                // If any ACR was requested, fail if the ACR value in the id token is not present or does not match
                if (!requestedAcrValues.isEmpty()) {
                    ACR idTokenAcr = idToken.getACR();
                    if (idTokenAcr == null || !requestedAcrValues.contains(idTokenAcr.getValue())) {
                        throw new OIDCProviderException("Invalid ACR in id token. Requested: "
                            + String.join(", ", requestedAcrValues) + " Received: " + idTokenAcr);
                    }
                }
            }
        }
    }

    private OIDCTokenResponse requestTokenFromAuthenticationResponse(
        AuthenticationSuccessResponse authenticationSuccessResponse) throws Exception
    {
        this.logger.debug("Getting the access token from the token endpoint");
        ClientAuthentication authentication = this.configuration.getClientAuthentication();

        // Generate callback URL
        URI callback = this.oidc.createEndPointURI(CallbackOIDCEndpoint.HINT);

        // PKCE support
        CodeVerifier codeVerifier = this.configuration.getSessionCodeVerifier();

        // Get access token
        AuthorizationGrant authorizationGrant =
            new AuthorizationCodeGrant(authenticationSuccessResponse.getAuthorizationCode(), callback, codeVerifier);

        Endpoint tokenEndpoint = this.configuration.getTokenOIDCEndpoint();
        Scope scope = this.configuration.getScope();
        TokenRequest tokenRequest;
        if (authentication != null) {
            tokenRequest = new TokenRequest(tokenEndpoint.getURI(), authentication, authorizationGrant, scope);
        } else {
            tokenRequest =
                new TokenRequest(tokenEndpoint.getURI(), this.configuration.getClientID(), authorizationGrant, scope);
        }

        return OIDCTokenRequestHelper.requestTokenHTTP(tokenRequest, this.configuration.getTokenOIDCEndpoint());
    }
}
