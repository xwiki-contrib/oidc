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
import java.text.ParseException;
import java.util.Date;
import java.util.Map;

import org.apache.commons.lang3.time.DurationFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderException;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
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
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

/**
 * Internal helper to help making token requests.
 *
 * @version $Id$
 * @since 2.16.0
 */
public final class OIDCTokenRequestHelper
{
    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCTokenRequestHelper.class);

    /**
     * The non-standard token response parameter in which Keycloak indicates the lifetime of the refresh token.
     */
    private static final String REFRESH_EXPIRES_IN = "refresh_expires_in";

    /**
     * The non-standard token response parameter in which Microsoft Entra ID indicates the lifetime of the refresh
     * token.
     */
    private static final String REFRESH_TOKEN_EXPIRES_IN = "refresh_token_expires_in";

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
        ClientAuthentication authentication = null;
        if (secret != null) {
            if (method == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
                authentication = new ClientSecretPost(clientID, secret);
            } else {
                authentication = new ClientSecretBasic(clientID, secret);
            }

            LOGGER.debug("Authenticating the client [{}] with the method [{}]", clientID,
                authentication.getMethod());
        }

        return authentication;
    }

    /**
     * Make an HTTP request to get an OAuth2 or OIDC token.
     *
     * @param tokenRequest the request
     * @param tokenEndpoint the endpoint to use
     * @return the response
     * @throws GeneralException if an error occurred when parsing the response
     * @throws IOException if an error occurred while making the request
     * @throws OIDCProviderException if no access token is to be found in the response
     */
    public static OIDCTokenResponse requestTokenHTTP(TokenRequest tokenRequest, Endpoint tokenEndpoint)
        throws GeneralException, IOException, OIDCProviderException
    {
        HTTPRequest tokenHTTP = tokenRequest.toHTTPRequest();

        if (tokenEndpoint != null) {
            tokenEndpoint.prepare(tokenHTTP);
        }

        // Don't log the values of the headers and of the response, they contain the client secret and the tokens
        LOGGER.debug("OIDC Token request ({}, headers {})", tokenHTTP.getURL(), tokenHTTP.getHeaderMap().keySet());

        HTTPResponse httpResponse = tokenHTTP.send();
        LOGGER.debug("OIDC Token response status [{}]", httpResponse.getStatusCode());

        if (httpResponse.getStatusCode() != HTTPResponse.SC_OK) {
            TokenErrorResponse error = TokenErrorResponse.parse(httpResponse);

            LOGGER.debug("Failed to get access token ([{}])",
                error.getErrorObject() != null ? error.getErrorObject() : httpResponse.getStatusCode());

            if (error.getErrorObject() != null) {
                throw new OIDCProviderException("Failed to get access token", error.getErrorObject());
            } else {
                throw new OIDCProviderException(String.format("Failed to get access token (%s) : [%s]",
                    httpResponse.getStatusCode(), httpResponse.getBody()));
            }
        }

        return OIDCTokenResponse.parse(httpResponse);
    }

    /**
     * Find when the refresh token sent in a token response expires. The OAuth2 standard does not provide this
     * information, so it's taken from the non-standard parameters some providers add to the token response
     * ({@code refresh_expires_in} or {@code refresh_token_expires_in}) or, when the refresh token is a JWT, from its
     * {@code exp} claim.
     *
     * @param response the token response
     * @return the expiration date of the refresh token, or {@code null} if the response does not contain a refresh
     *         token or does not indicate when it expires
     * @since 2.31.0
     */
    public static Date getRefreshTokenExpirationDate(AccessTokenResponse response)
    {
        RefreshToken refreshToken = response.getTokens().getRefreshToken();
        if (refreshToken == null) {
            return null;
        }

        Map<String, Object> parameters = response.getCustomParameters();
        Long lifetime = getLifetime(parameters.get(REFRESH_EXPIRES_IN));
        if (lifetime == null) {
            lifetime = getLifetime(parameters.get(REFRESH_TOKEN_EXPIRES_IN));
        }
        if (lifetime != null) {
            return new Date(System.currentTimeMillis() + lifetime * 1000);
        }

        try {
            return JWTParser.parse(refreshToken.getValue()).getJWTClaimsSet().getExpirationTime();
        } catch (ParseException e) {
            // The refresh token is not a JWT (or not a valid one), so it cannot tell when it expires
            return null;
        }
    }

    /**
     * @param value the value of a token response parameter indicating a lifetime in seconds
     * @return the lifetime in seconds, or {@code null} if the value is not a positive number (a lifetime of 0 means no
     *         expiration for Keycloak)
     */
    private static Long getLifetime(Object value)
    {
        Long lifetime = null;
        if (value instanceof Number) {
            lifetime = ((Number) value).longValue();
        } else if (value instanceof String) {
            try {
                lifetime = Long.valueOf((String) value);
            } catch (NumberFormatException e) {
                // Not a lifetime
            }
        }

        return lifetime != null && lifetime > 0 ? lifetime : null;
    }

    /**
     * Log, in debug, when the refresh token sent in a token response expires.
     *
     * @param response the token response
     * @param logger the logger to use
     * @since 2.31.0
     */
    public static void logRefreshTokenExpiration(AccessTokenResponse response, Logger logger)
    {
        if (logger.isDebugEnabled()) {
            if (response.getTokens().getRefreshToken() == null) {
                logger.debug("The token response does not contain a refresh token");
            } else {
                Date expiration = getRefreshTokenExpirationDate(response);
                if (expiration != null) {
                    logRefreshTokenExpiration(expiration, logger);
                } else {
                    logger.debug("The provider did not indicate when the refresh token expires");
                }
            }
        }
    }

    private static void logRefreshTokenExpiration(Date expiration, Logger logger)
    {
        // Rounded to the second, since the provider indicates the lifetime in seconds
        long remaining = Math.round((expiration.getTime() - System.currentTimeMillis()) / 1000.0) * 1000;
        if (remaining > 0) {
            logger.debug("The refresh token expires on [{}], in [{}]", expiration,
                DurationFormatUtils.formatDurationWords(remaining, true, true));
        } else {
            logger.debug("The refresh token already expired on [{}]", expiration);
        }
    }
}
