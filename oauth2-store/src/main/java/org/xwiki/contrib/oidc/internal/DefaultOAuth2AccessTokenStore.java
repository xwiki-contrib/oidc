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

import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.contrib.oidc.OAuth2AccessTokenStore;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;

import com.nimbusds.oauth2.sdk.token.AccessToken;

import groovy.lang.Singleton;

/**
 * Default implementation for the {@link org.xwiki.contrib.oidc.OAuth2AccessTokenStore}.
 *
 * @version $Id$
 * @since 2.14.0
 */
@Component
@Singleton
public class DefaultOAuth2AccessTokenStore extends AbstractOAuth2AccessTokenStore
{
    @Inject
    private ComponentManager componentManager;

    @Override
    public void setAccessToken(OIDCClientConfiguration configuration, AccessToken accessToken) throws OAuth2Exception
    {
        getStore(configuration.getTokenScope().name().toLowerCase()).setAccessToken(configuration, accessToken);
    }

    @Override
    public AccessToken getAccessToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        return getStore(configuration.getTokenScope().name().toLowerCase()).getAccessToken(configuration);
    }

    private OAuth2AccessTokenStore getStore(String hint) throws OAuth2Exception
    {
        if (componentManager.hasComponent(OAuth2AccessTokenStore.class, hint)) {
            try {
                return componentManager.getInstance(OAuth2AccessTokenStore.class, hint);
            } catch (ComponentLookupException e) {
                // Shouldn't happen
                throw new OAuth2Exception(String.format("Failed to load access token store with hint [%s]", hint));
            }
        } else {
            throw new OAuth2Exception(String.format("No access token store is available with hint [%s]", hint));
        }
    }
}
