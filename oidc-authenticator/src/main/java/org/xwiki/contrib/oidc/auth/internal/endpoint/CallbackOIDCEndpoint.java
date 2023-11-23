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

import java.net.URI;
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
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;
import org.xwiki.observation.ObservationManager;
import org.xwiki.security.authentication.UserAuthenticatedEvent;
import org.xwiki.user.UserReferenceResolver;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.Response;
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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
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

        // Validate state
        State state = authorizationResponse.getState();
        if (!Objects.equals(state != null ? state.getValue() : null, this.configuration.getSessionState())) {
            this.logger.debug("OIDC callback: Invalid state (was expecting [{}] and got [{}])",
                this.configuration.getSessionState(), state);

            throw new OIDCException(
                "Invalid state: was expecting [" + this.configuration.getSessionState() + "] and got [" + state + "]");
        }
        // TODO: remove the state from the session ?

        // Deal with errors
        if (!authorizationResponse.indicatesSuccess()) {
            // Cast to error response
            AuthorizationErrorResponse errorResponse = (AuthorizationErrorResponse) authorizationResponse;

            // If impossible to authenticate without prompt, just ignore and redirect
            if (OIDCError.INTERACTION_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())
                || OIDCError.LOGIN_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())) {
                this.logger.debug("OIDC callback: Impossible to authenticate, redirect to ([{}])",
                    authorizationResponse.getState().getValue());

                // Redirect to original request
                return new RedirectResponse(new URI(authorizationResponse.getState().getValue()));
            }

            // Unknown error
            throw new OIDCException("Unexpected error [" + errorResponse.getErrorObject().getCode() + "] : "
                + errorResponse.getErrorObject().getDescription());
        }

        // Cast to success response
        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;

        // Get authorization code
        AuthorizationCode code = successResponse.getAuthorizationCode();

        // Generate callback URL
        URI callback = this.oidc.createEndPointURI(CallbackOIDCEndpoint.HINT);

        // Get access token
        AuthorizationGrant authorizationGrant = new AuthorizationCodeGrant(code, callback);

        Issuer issuer = authorizationResponse.getIssuer();
        ClientID clientID = this.configuration.getClientID(issuer);

        TokenRequest tokeRequest;
        Secret secret = this.configuration.getSecret();
        Endpoint tokenEndpoint = this.configuration.getTokenOIDCEndpoint();
        if (secret != null) {
            this.logger.debug("OIDC callback: adding secret ({} {})", clientID, secret.getValue());

            ClientAuthentication clientSecret;
            if (this.configuration.getTokenEndPointAuthMethod() == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
                clientSecret = new ClientSecretPost(clientID, secret);
            } else {
                clientSecret = new ClientSecretBasic(clientID, secret);
            }
            tokeRequest = new TokenRequest(tokenEndpoint.getURI(), clientSecret, authorizationGrant);
        } else {
            tokeRequest = new TokenRequest(tokenEndpoint.getURI(), clientID, authorizationGrant);
        }

        HTTPRequest tokenHTTP = tokeRequest.toHTTPRequest();
        tokenEndpoint.prepare(httpRequest);

        this.logger.debug("OIDC Token request ({}?{},{},{})", tokenHTTP.getURL(), tokenHTTP.getURL(),
            tokenHTTP.getAuthorization(), tokenHTTP.getHeaderMap());

        HTTPResponse httpResponse = tokenHTTP.send();
        this.logger.debug("OIDC Token response ({})", httpResponse.getBody());

        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            TokenErrorResponse error = TokenErrorResponse.parse(httpResponse);

            this.logger.debug("OIDC callback: Failed to get access token ([{}])",
                error.getErrorObject() != null ? error.getErrorObject() : httpResponse.getStatusCode());

            if (error.getErrorObject() != null) {
                throw new OIDCException("Failed to get access token", error.getErrorObject());
            } else {
                throw new OIDCException("Failed to get access token (" + httpResponse.getStatusCode() + ')');
            }
        }

        OIDCTokenResponse tokenResponse = OIDCTokenResponse.parse(httpResponse);

        // Parse and validate the id token
        ClientProvider clientProvider = this.configuration.getClientProvider(issuer);
        IDTokenClaimsSet idToken;
        if (clientProvider != null) {
            idToken = IDTokenValidator.create(clientProvider.getMetadata(),
                this.configuration.createClientInformation(issuer), this.oidc.getJWKSource())
                .validate(tokenResponse.getOIDCTokens().getIDToken(), null);
        } else {
            // TODO: add support for null ClientProvider
            idToken = new IDTokenClaimsSet(tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet());
        }

        BearerAccessToken accessToken = tokenResponse.getTokens().getBearerAccessToken();

        HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();

        // Store the access token in the session
        this.configuration.setIdToken(idToken);
        this.configuration.setAccessToken(accessToken);

        // Update/Create XWiki user
        SimplePrincipal principal = this.users.updateUserInfo(accessToken);

        // Remember user in the session
        session.setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);

        // Indicate that the user is now authenticated
        this.observationManager.notify(new UserAuthenticatedEvent(this.userResolver.resolve(principal.getName())),
            null);
        // Remember the session of that OIDC user (to be able to do back channel logout)
        this.sessions.onLogin(session, idToken.getSubject());

        // TODO: put enough information in the cookie to automatically authenticate when coming back after the session
        // is lost

        this.logger.debug("OIDC callback: principal=[{}]", principal);
        this.logger.debug("OIDC callback: redirect=[{}]", this.configuration.getSuccessRedirectURI());

        // Redirect to original request
        return new RedirectResponse(this.configuration.getSuccessRedirectURI());
    }
}
