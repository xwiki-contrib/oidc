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
import java.security.Principal;
import java.util.Objects;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.securityfilter.filter.SecurityRequestWrapper;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.auth.internal.Endpoint;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.OIDCUserManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;

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
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Token endpoint for OpenID Connect.
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
    private Logger logger;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        this.logger.debug("OIDC callback: starting with request [{}]", httpRequest.getURL());

        // Parse the request
        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(httpRequest);

        // Validate state
        State state = authorizationResponse.getState();
        if (!Objects.equals(state.getValue(), this.configuration.getSessionState())) {
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

        TokenRequest tokeRequest;
        Secret secret = this.configuration.getSecret();
        Endpoint tokenEndpoint = this.configuration.getTokenOIDCEndpoint();
        if (secret != null) {
            this.logger.debug("OIDC callback: adding secret ({} {})", this.configuration.getClientID(),
                secret.getValue());

            ClientAuthentication clientSecret;
            if (this.configuration.getTokenEndPointAuthMethod() == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
                clientSecret = new ClientSecretPost(this.configuration.getClientID(), secret);
            } else {
                clientSecret = new ClientSecretBasic(this.configuration.getClientID(), secret);
            }
            tokeRequest = new TokenRequest(tokenEndpoint.getURI(), clientSecret, authorizationGrant);
        } else {
            tokeRequest =
                new TokenRequest(tokenEndpoint.getURI(), this.configuration.getClientID(), authorizationGrant);
        }

        HTTPRequest tokenHTTP = tokeRequest.toHTTPRequest();
        tokenEndpoint.prepare(httpRequest);

        this.logger.debug("OIDC Token request ({}?{},{},{})", tokenHTTP.getURL(), tokenHTTP.getQuery(),
            tokenHTTP.getAuthorization(), tokenHTTP.getHeaderMap());

        HTTPResponse httpResponse = tokenHTTP.send();
        this.logger.debug("OIDC Token response ({})", httpResponse.getContent());

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

        // TODO: validate the signature of the id token

        IDTokenClaimsSet idToken = new IDTokenClaimsSet(tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet());
        BearerAccessToken accessToken = tokenResponse.getTokens().getBearerAccessToken();

        HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();

        // Store the access token in the session
        this.configuration.setIdToken(idToken);
        this.configuration.setAccessToken(accessToken);

        // Update/Create XWiki user
        Principal principal = this.users.updateUserInfo(accessToken);

        // Remember user in the session
        session.setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);

        // TODO: put enough information in the cookie to automatically authenticate when coming back

        this.logger.debug("OIDC callback: principal=[{}]", principal);
        this.logger.debug("OIDC callback: redirect=[{}]", this.configuration.getSuccessRedirectURI());

        // Redirect to original request
        return new RedirectResponse(this.configuration.getSuccessRedirectURI());
    }
}
