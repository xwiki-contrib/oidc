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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.securityfilter.filter.SecurityRequestWrapper;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.OIDCUserManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;

import com.google.common.base.Objects;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.AuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Token endpoint for OpenId Connect.
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
    private OIDCUserManager users;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        AuthorizationResponse authorizationResponse = AuthorizationResponse.parse(httpRequest);

        // Validate state
        State state = authorizationResponse.getState();
        if (!Objects.equal(state, this.configuration.getSessionState())) {
            throw new OIDCException("Invalid state [" + state + "]");
        }
        // TODO: remove the state from the session ?

        // Deal with errors
        if (!authorizationResponse.indicatesSuccess()) {
            // Cast to error response
            AuthorizationErrorResponse errorResponse = (AuthorizationErrorResponse) authorizationResponse;

            // If impossible to authenticate without prompt, just ignore and redirect
            if (OIDCError.INTERACTION_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())
                || OIDCError.LOGIN_REQUIRED.getCode().equals(errorResponse.getErrorObject().getCode())) {
                // Redirect to original request
                return new RedirectResponse(new URI(authorizationResponse.getState().getValue()));
            }
        }

        // Cast to success response
        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) authorizationResponse;

        // Get authorization code
        AuthorizationCode code = successResponse.getAuthorizationCode();

        // Get access token
        AuthorizationGrant authorizationGrant =
            new AuthorizationCodeGrant(code, authorizationResponse.getRedirectionURI());
        // TODO: setup some client authentication, secret, all that
        TokenRequest tokeRequest = new TokenRequest(this.configuration.getTokenOIDCEndpoint(),
            this.configuration.getClientID(), authorizationGrant);
        HTTPRequest tokenHTTP = tokeRequest.toHTTPRequest();
        tokenHTTP.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
            + this.getClass().getPackage().getImplementationVersion());
        HTTPResponse httpResponse = tokenHTTP.send();

        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            TokenErrorResponse error = TokenErrorResponse.parse(httpResponse);
            throw new OIDCException("Failed to get access token", error.getErrorObject());
        }

        OIDCTokenResponse tokenResponse = OIDCTokenResponse.parse(httpResponse);

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

        // Redirect to original request
        return new RedirectResponse(this.configuration.getSuccessRedirectURI());
    }
}
