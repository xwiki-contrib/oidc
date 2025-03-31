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
package org.xwiki.contrib.oidc.auth.internal;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;

import com.nimbusds.oauth2.sdk.GeneralException;
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
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

/**
 * Internal helper to help making token requests.
 *
 * @version $Id$
 * @since 2.15.1
 */
public final class OIDCTokenRequestHelper
{
    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCTokenRequestHelper.class);

    private OIDCTokenRequestHelper()
    {
        // Empty constructor
    }

    /**
     * Based on the authentication method, provide the corresponding {@link ClientAuthentication}.
     *
     * @param method the method to use
     * @param clientID the client ID
     * @param secret the client secret
     * @return the corresponding authentication
     */
    public static ClientAuthentication getClientAuthentication(ClientAuthenticationMethod method,
        ClientID clientID, Secret secret)
    {
        if (secret != null) {
            LOGGER.debug("Adding secret ({} {})", clientID, secret.getValue());

            if (method == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
                return new ClientSecretPost(clientID, secret);
            } else {
                return new ClientSecretBasic(clientID, secret);
            }
        }

        return null;
    }

    /**
     * Make an HTTP request to get an OAuth2 or OIDC token.
     *
     * @param tokenRequest the request
     * @param tokenEndpoint the endpoint to use
     * @return the response
     * @throws GeneralException if an error occurred when parsing the response
     * @throws IOException if an error occurred while making the request
     * @throws OIDCException if no access token is to be found in the response
     */
    public static OIDCTokenResponse requestTokenHTTP(TokenRequest tokenRequest, Endpoint tokenEndpoint)
        throws GeneralException, IOException, OIDCException
    {
        HTTPRequest tokenHTTP = tokenRequest.toHTTPRequest();

        if (tokenEndpoint != null) {
            tokenEndpoint.prepare(tokenHTTP);
        }

        LOGGER.debug("OIDC Token request ({},{},{})", tokenHTTP.getURL(), tokenHTTP.getAuthorization(),
            tokenHTTP.getHeaderMap());

        HTTPResponse httpResponse = tokenHTTP.send();
        LOGGER.debug("OIDC Token response ({})", httpResponse.getBody());

        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            TokenErrorResponse error = TokenErrorResponse.parse(httpResponse);

            LOGGER.debug("Failed to get access token ([{}])",
                error.getErrorObject() != null ? error.getErrorObject() : httpResponse.getStatusCode());

            if (error.getErrorObject() != null) {
                throw new OIDCException("Failed to get access token", error.getErrorObject());
            } else {
                throw new OIDCException("Failed to get access token (" + httpResponse.getStatusCode() + ')');
            }
        }

        return OIDCTokenResponse.parse(httpResponse);
    }
}
