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
package org.xwiki.contrib.oidc.provider.internal.endpoint;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * Token endpoint for OpenId Connect.
 * 
 * @version $Id$
 */
@Component
@Named(TokenOIDCEndpoint.HINT)
@Singleton
public class TokenOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "token";

    @Inject
    private OIDCStore store;

    @Inject
    private OIDCManager manager;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        TokenRequest request = TokenRequest.parse(httpRequest);

        AuthorizationGrant authorizationGrant = request.getAuthorizationGrant();

        // TODO: authenticate the client if needed
        if (authorizationGrant.getType().requiresClientAuthentication()) {
            ClientAuthentication authentication = request.getClientAuthentication();
            // TODO
        }

        if (authorizationGrant.getType() == GrantType.AUTHORIZATION_CODE) {
            AuthorizationCodeGrant grant = (AuthorizationCodeGrant) authorizationGrant;

            OIDCConsent consent =
                this.store.getConsent(request.getClientID(), grant.getRedirectionURI(), grant.getAuthorizationCode());

            if (consent == null) {
                return new TokenErrorResponse(OAuth2Error.INVALID_GRANT);
            }

            // Generate new access token
            // TODO: set a configurable lifespan ?
            consent.setAccessToken(new BearerAccessToken());

            // Reset authorization code
            consent.setAuthorizationCode(null);

            // Store new access token
            this.store.saveConsent(consent, "Store new OIDC access token");

            JWT idToken = this.manager.createdIdToken(request.getClientID(), consent.getUserReference(), null);
            OIDCTokens tokens = new OIDCTokens(idToken, consent.getAccessToken(), null);

            return new OIDCTokenResponse(tokens);
        }

        return new TokenErrorResponse(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
    }
}
