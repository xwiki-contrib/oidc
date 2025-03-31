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
package org.xwiki.contrib.oidc.internal;

import java.net.URI;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.auth.internal.OIDCTokenRequestHelper;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.job.AbstractJob;
import org.xwiki.job.DefaultJobStatus;
import org.xwiki.job.DefaultRequest;

import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

/**
 * Job for renewing OAuth2 access tokens, using OAuth2 renew tokens.
 *
 * @version $Id$
 * @since 2.16.0
 */
@Component
@Singleton
@Named(OAuth2TokenRenewalJob.JOB_TYPE)
public class OAuth2TokenRenewalJob extends AbstractJob<DefaultRequest, DefaultJobStatus<DefaultRequest>>
{
    /**
     * The job type.
     */
    public static final String JOB_TYPE = "oauth2/tokenRenewal";

    /**
     * The name of the property used to get the token to renew.
     */
    public static final String TOKEN_PROPERTY = "token";

    @Inject
    private org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration authConfig;

    @Inject
    private OAuth2TokenStore store;

    @Override
    public String getType()
    {
        return JOB_TYPE;
    }

    @Override
    protected void runInternal() throws Exception
    {
        Object genericToken = request.getProperty(OAuth2TokenRenewalJob.TOKEN_PROPERTY);

        // Verify that the token is what we expect
        if (genericToken instanceof NimbusOAuth2Token) {
            NimbusOAuth2Token token = (NimbusOAuth2Token) genericToken;

            // Verify that the configuration works
            OIDCClientConfiguration configuration = token.getConfiguration();

            if (configuration != null && token.toRefreshToken() != null) {
                renewToken(configuration, token);
            } else if (configuration == null) {
                logger.error("Not renewing token [{}] as its configuration [{}] does not exist",
                    token.getReference(), token.getConfiguration());
            } else {
                logger.error("Not renewing token [{}] as no renew token exist", token.getReference());
            }
        } else {
            logger.error("Invalid token [{}] provided for renewal", genericToken);
        }
    }

    private void renewToken(OIDCClientConfiguration configuration, NimbusOAuth2Token token) throws Exception
    {
        try {
            OIDCTokenResponse response = requestTokenFromRefreshToken(token, configuration);

            token.fromAccessToken(response.getTokens().getAccessToken());
            token.fromRefreshToken(response.getTokens().getRefreshToken());

            store.saveToken(token);
        } catch (Exception e) {
            logger.error("Failed to renew token [{}]", token.getReference(), e);

            // In case the renewal fails, we need to check if the access token currently stored is still valid.
            // If it is not, then we can clean it up.
            if (token.toAccessToken().getLifetime() <= 0) {
                store.deleteToken(token);
            }

            throw new OAuth2Exception(String.format("Failed to renew token [%s] for configuration [%s]",
                token.getReference(), configuration.getConfigurationName()));
        }
    }

    private OIDCTokenResponse requestTokenFromRefreshToken(NimbusOAuth2Token token,
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration storedConfiguration)
        throws Exception
    {
        RefreshToken refreshToken = token.toRefreshToken();
        URI tokenEndpointURI = new URI(storedConfiguration.getTokenEndpoint());

        if (refreshToken != null) {
            AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(refreshToken);

            ClientAuthentication authentication = OIDCTokenRequestHelper.getClientAuthentication(
                authConfig.toClientAuthenticationMethod(storedConfiguration.getTokenEndpointAuthMethod()),
                new ClientID(storedConfiguration.getClientId()),
                new Secret(storedConfiguration.getClientSecret()));

            TokenRequest tokenRequest =
                new TokenRequest(tokenEndpointURI, authentication, refreshTokenGrant, null);

            return OIDCTokenRequestHelper.requestTokenHTTP(tokenRequest, null);
        }

        return null;
    }
}
