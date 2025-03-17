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
import java.util.Objects;

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
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.OIDCUserManager;
import org.xwiki.contrib.oidc.auth.internal.session.ClientHttpSessions;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders.ClientProvider;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.ErrorResponse;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;
import org.xwiki.observation.ObservationManager;
import org.xwiki.security.authentication.UserAuthenticatedEvent;
import org.xwiki.user.UserReferenceResolver;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.ResponseType.Value;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
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
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

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

    @Inject
    private Container container;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCManager oidc;

    @Inject
    private OIDCUserManager users;

    @Inject
    private ObservationManager observationManager;

    @Inject
    @Named("document")
    private UserReferenceResolver<String> userResolver;

    @Inject
    private ClientHttpSessions sessions;

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

        // Validate state
        String sessionState = this.configuration.removeSessionState();
        if (sessionState == null) {
            return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST,
                "No state could be found in the current OpenID Connection session"
                    + " which suggest it was lost or that this callback endpoint was called directly");
        } else {
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
        }

        // Deal with errors
        if (!authorizationResponse.indicatesSuccess()) {
            // Cast to error response
            AuthorizationErrorResponse errorResponse = (AuthorizationErrorResponse) authorizationResponse;

            // If impossible to authenticate without prompt, just ignore and redirect
            if (OIDCError.INTERACTION_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())
                || OIDCError.LOGIN_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())) {
                this.logger.debug("Impossible to authenticate, redirect to ([{}])",
                    authorizationResponse.getState().getValue());

                // Redirect to original request
                return new RedirectResponse(new URI(authorizationResponse.getState().getValue()));
            }

            // Unknown error
            return new ErrorResponse(HTTPResponse.SC_SERVER_ERROR, "Unexpected error ["
                + errorResponse.getErrorObject().getCode() + "] : " + errorResponse.getErrorObject().getDescription());
        }

        // Get the authentication response
        // TODO: it's a bit strange that there is not a more natural way to directly parse a AuthenticationResponse
        // or convert a AuthorizationSuccessResponse
        AuthenticationSuccessResponse authenticationResponse = AuthenticationSuccessResponse.parse(httpRequest);

        ResponseType responseType = authenticationResponse.impliedResponseType();

        this.logger.debug("Auth response: the provider sent back the response type [{}]", responseType);

        // Validate the id token, if provided
        IDTokenClaimsSet idToken = null;
        if (authenticationResponse.getIDToken() != null) {
            idToken = parseIdToken(this.configuration.removeSessionNonce(), authenticationResponse.getIDToken(),
                authenticationResponse.getIssuer());
        }
        this.logger.debug("Auth response: the provider sent back the id token [{}]", idToken);

        // Get the access token
        AccessToken accessToken = authenticationResponse.getAccessToken();
        RefreshToken refreshToken = null;

        this.logger.debug("Auth response: the provider sent back the access token [{}]", accessToken);
        if (accessToken == null) {
            this.logger.debug("Auth response: the provider did not sent back the authorization code [{}]",
                authenticationResponse.getAuthorizationCode());

            if (authenticationResponse.getAuthorizationCode() != null) {
                OIDCTokenResponse tokenResponse = requestToken(authenticationResponse.getAuthorizationCode(),
                    authenticationResponse.getIssuer(), this.configuration.getScope());

                accessToken = tokenResponse.getTokens().getBearerAccessToken();
                refreshToken = tokenResponse.getTokens().getRefreshToken();

                // Store the access token in the session
                this.configuration.setAccessToken(accessToken, tokenResponse.getTokens().getRefreshToken());

                // Also parse and validate the id token if we don't already have it
                if (configuration.isAuthenticationConfiguration() && idToken == null) {
                    idToken = parseIdToken(null, tokenResponse.getOIDCTokens().getIDToken(),
                        authenticationResponse.getIssuer());
                }
            }
        } else {
            // Store the access token in the session
            this.configuration.setAccessToken(accessToken, null);
        }

        if (configuration.isAuthenticationConfiguration()) {
            // Make sure there is an id token
            if (idToken == null) {
                return new ErrorResponse(HTTPResponse.SC_BAD_REQUEST, "No id token could be found");
            }

            UserInfo userInfo;
            if (accessToken != null && responseType.contains(Value.CODE) && !this.configuration.isUserInfoSkipped()) {
                this.logger.debug("Requesting the userinfo from a dedicated endpoint");

                // Request the user info from a dedicated endpoint if it's a code (or hybrid) flow
                userInfo = this.users.getUserInfo(accessToken);
            } else {
                this.logger.debug("Using the id token as userinfo");

                // Simulate a UserInfo based on the id token
                userInfo = new UserInfo(idToken.toJSONObject());
            }

            // Update/Create XWiki user
            SimplePrincipal principal = this.users.updateUser(idToken, userInfo, accessToken);

            // Remember user in the session
            HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();
            session.setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);

            // Indicate that the user is now authenticated
            this.observationManager.notify(new UserAuthenticatedEvent(this.userResolver.resolve(principal.getName())),
                null);
            // Remember the session of that OIDC user (to be able to do back channel logout)
            this.sessions.onLogin(session, idToken.getSubject());

            // TODO: put enough information in the cookie to automatically authenticate when coming back after the session
            // is lost

            this.logger.debug("OIDC callback: principal=[{}]", principal);
        }

        this.configuration.storeTokens(accessToken, refreshToken);

        this.logger.debug("OIDC callback: redirect=[{}]", this.configuration.getSuccessRedirectURI());

        // Redirect to original request
        return new RedirectResponse(this.configuration.getSuccessRedirectURI());
    }

    private OIDCTokenResponse requestToken(AuthorizationCode code, Issuer issuer, Scope scope)
        throws URISyntaxException, GeneralException, IOException, OIDCException
    {
        this.logger.debug("Getting the access token from the token endpoint");

        // Generate callback URL
        URI callback = this.oidc.createEndPointURI(CallbackOIDCEndpoint.HINT);

        // Get access token
        AuthorizationGrant authorizationGrant = new AuthorizationCodeGrant(code, callback);

        TokenRequest tokeRequest;
        Secret secret = this.configuration.getSecret();
        Endpoint tokenEndpoint = this.configuration.getTokenOIDCEndpoint();
        ClientID clientID = this.configuration.getClientID(issuer);
        if (secret != null) {
            this.logger.debug("Adding secret ({} {})", clientID, secret.getValue());

            ClientAuthentication clientSecret;
            if (this.configuration.getTokenEndPointAuthMethod() == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
                clientSecret = new ClientSecretPost(clientID, secret);
            } else {
                clientSecret = new ClientSecretBasic(clientID, secret);
            }
            tokeRequest = new TokenRequest(tokenEndpoint.getURI(), clientSecret, authorizationGrant, scope);
        } else {
            tokeRequest = new TokenRequest(tokenEndpoint.getURI(), clientID, authorizationGrant, scope);
        }

        HTTPRequest tokenHTTP = tokeRequest.toHTTPRequest();
        tokenEndpoint.prepare(tokenHTTP);

        this.logger.debug("OIDC Token request ({}?{},{},{})", tokenHTTP.getURL(), tokenHTTP.getURL(),
            tokenHTTP.getAuthorization(), tokenHTTP.getHeaderMap());

        HTTPResponse httpResponse = tokenHTTP.send();
        this.logger.debug("OIDC Token response ({})", httpResponse.getBody());

        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            TokenErrorResponse error = TokenErrorResponse.parse(httpResponse);

            this.logger.debug("Failed to get access token ([{}])",
                error.getErrorObject() != null ? error.getErrorObject() : httpResponse.getStatusCode());

            if (error.getErrorObject() != null) {
                throw new OIDCException("Failed to get access token", error.getErrorObject());
            } else {
                throw new OIDCException("Failed to get access token (" + httpResponse.getStatusCode() + ')');
            }
        }

        return OIDCTokenResponse.parse(httpResponse);
    }

    private IDTokenClaimsSet parseIdToken(Nonce nonce, JWT token, Issuer issuer) throws GeneralException, IOException,
        URISyntaxException, BadJOSEException, JOSEException, ParseException, OIDCException
    {
        // Parse and validate the id token
        ClientProvider clientProvider = this.configuration.getClientProvider(issuer);

        IDTokenClaimsSet idToken;
        if (clientProvider != null) {
            idToken = IDTokenValidator.create(clientProvider.getMetadata(),
                this.configuration.createClientInformation(issuer), this.oidc.getJWKSource()).validate(token, nonce);
        } else {
            // TODO: add support for null ClientProvider
            idToken = new IDTokenClaimsSet(token.getJWTClaimsSet());
        }

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
                        throw new OIDCException("Invalid ACR in id token. Requested: "
                            + String.join(", ", requestedAcrValues) + " Received: " + idTokenAcr);
                    }
                }
            }
        }

        this.logger.debug("OIDC Id Token: {}", idToken);

        // Store the original id token as sent by the provider
        this.configuration.setIdTokenJWT(token);
        // Store the id token in the session
        this.configuration.setIdToken(idToken);

        return idToken;
    }
}
