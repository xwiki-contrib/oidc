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
package org.xwiki.contrib.oidc;

import java.net.URI;
import java.net.URISyntaxException;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.bridge.DocumentAccessBridge;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.internal.NimbusOAuth2Token;
import org.xwiki.job.Job;
import org.xwiki.query.QueryException;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.stability.Unstable;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.xpn.xwiki.XWikiException;

/**
 * Script service to deal with OAuth2 authorizations.
 *
 * @version $Id$
 * @since 2.15.0
 */
@Unstable
@Component
@Singleton
@Named("oauth2client")
public class OAuth2ClientScriptService implements ScriptService
{
    @Inject
    private OAuth2ClientManager oAuth2ClientManager;

    @Inject
    private OIDCClientConfigurationStore clientConfigurationStore;

    @Inject
    private OAuth2TokenStore tokenStore;

    @Inject
    private ContextualAuthorizationManager authorizationManager;

    @Inject
    private DocumentAccessBridge documentAccessBridge;

    /**
     * Authorize a configuration.
     *
     * @param configurationName the name of the configuration to be authorized
     * @param redirectURI the redirect URI in case of an authorization success
     * @throws OAuth2Exception if an error happens
     */
    public void authorize(String configurationName, String redirectURI) throws OAuth2Exception
    {
        authorize(configurationName, redirectURI, false);
    }

    /**
     * Authorize a configuration.
     *
     * @param configurationName the name of the configuration to be authorized
     * @param redirectURI the redirect URI in case of an authorization success
     * @param force set to true if authorization should be performed even if a valid access token already exists.
     * Only wiki administrators can force the authorization.
     * @throws OAuth2Exception if an error happens
     */
    public void authorize(String configurationName, String redirectURI, boolean force) throws OAuth2Exception
    {
        boolean isWikiAdmin = authorizationManager.hasAccess(Right.ADMIN,
            documentAccessBridge.getCurrentDocumentReference().getWikiReference());

        try {
            OIDCClientConfiguration configuration = getConfigurationFromName(configurationName);

            if (OIDCClientConfiguration.TokenStorageScope.NONE.equals(configuration.getTokenStorageScope())) {
                throw new OAuth2Exception(
                    String.format("Configuration [%s] does not store tokens", configurationName));
            }

            if (!(force && isWikiAdmin)) {
                // Check if an access token already exists for this configuration
                OAuth2Token token = tokenStore.getToken(configuration);
                if (token instanceof NimbusOAuth2Token) {
                    AccessToken accessToken = ((NimbusOAuth2Token) token).toAccessToken();
                    if (accessToken != null && accessToken.getLifetime() > System.currentTimeMillis()) {
                        throw new OAuth2Exception(
                            String.format("Configuration [%s] is already authorized", configurationName));
                    }
                }
            }

            // Ensure that only wiki administrators can authorize applications wiki-wide
            if (OIDCClientConfiguration.TokenStorageScope.WIKI.equals(
                configuration.getTokenStorageScope()) && !isWikiAdmin) {
                throw new OAuth2Exception(String.format(
                    "Current user is not allowed to authorize configuration [%s] on scope [%s]",
                    configurationName, configuration.getConfigurationName()));
            }

            oAuth2ClientManager.authorize(configuration, new URI(redirectURI));
        } catch (URISyntaxException e) {
            throw new OAuth2Exception(String.format("Failed to authorize application [%s]", configurationName), e);
        }
    }

    /**
     * Get an up-to-date access token, renewing it if needed.
     *
     * @param configurationName the configuration to use
     * @return the access token found, or null if no access token exists
     * @throws OAuth2Exception if an error happens
     */
    public String getAccessToken(String configurationName) throws OAuth2Exception
    {
        return getAccessToken(configurationName, false);
    }

    /**
     * Get an access token.
     *
     * @since 2.17.2
     * @param configurationName the configuration to use
     * @param skipRenewal set to true to not attempt to renew an expiring token
     * @return the access token found, or null if no access token exists
     * @throws OAuth2Exception if an error happens
     */
    public String getAccessToken(String configurationName, boolean skipRenewal) throws OAuth2Exception
    {
        if (!skipRenewal) {
            // Make sure that the token is up to date
            OIDCClientConfiguration configuration = getConfigurationFromName(configurationName);
            Job tokenRenewalJob = oAuth2ClientManager.renew(configuration);
            if (tokenRenewalJob != null) {
                try {
                    tokenRenewalJob.join();
                } catch (InterruptedException e) {
                    throw new OAuth2Exception(String.format("Failed to renew token [%s]", configurationName), e);
                }
            }
        }

        OAuth2Token token = tokenStore.getToken(getConfigurationFromName(configurationName));
        if (token != null) {
            return token.getAccessToken();
        } else {
            return null;
        }
    }


    private OIDCClientConfiguration getConfigurationFromName(String name) throws OAuth2Exception
    {
        try {
            OIDCClientConfiguration configuration = clientConfigurationStore.getOIDCClientConfiguration(name);
            if (configuration == null) {
                throw new OAuth2Exception(String.format("No configuration found for [%s]", name));
            }

            return configuration;
        } catch (QueryException | XWikiException e) {
            throw new OAuth2Exception(String.format("Failed to load configuration [%s]", name), e);
        }
    }
}
