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

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/**
 * Default implementation for the {@link OAuth2TokenStore}.
 *
 * @version $Id$
 * @since 2.15.0
 */
@Component
@Singleton
public class DefaultOAuth2TokenStore extends AbstractOAuth2TokenStore
{
    @Inject
    private ComponentManager componentManager;

    @Override
    public void setToken(OIDCClientConfiguration configuration, AccessToken accessToken, RefreshToken refreshToken)
        throws OAuth2Exception
    {
        getStore(getStorageHint(configuration)).setToken(configuration, accessToken, refreshToken);
    }

    @Override
    public AccessToken getAccessToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        return getStore(getStorageHint(configuration)).getAccessToken(configuration);
    }

    @Override
    public RefreshToken getRefreshToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        return getStore(getStorageHint(configuration)).getRefreshToken(configuration);
    }

    private String getStorageHint(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        OIDCClientConfiguration.TokenStorageScope scope = configuration.getTokenStorageScope();
        if (!scope.equals(OIDCClientConfiguration.TokenStorageScope.NONE)) {
            return scope.name().toLowerCase();
        } else {
            throw new OAuth2Exception(String.format("Configuration [%s] does not store tokens.",
                configuration.getConfigurationName()));
        }
    }

    private OAuth2TokenStore getStore(String hint) throws OAuth2Exception
    {
        if (componentManager.hasComponent(OAuth2TokenStore.class, hint)) {
            try {
                return componentManager.getInstance(OAuth2TokenStore.class, hint);
            } catch (ComponentLookupException e) {
                // Shouldn't happen
                throw new OAuth2Exception(String.format("Failed to load access token store with hint [%s]", hint));
            }
        } else {
            throw new OAuth2Exception(String.format("No access token store is available with hint [%s]", hint));
        }
    }
}
