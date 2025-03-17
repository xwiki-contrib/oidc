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

import org.xwiki.component.annotation.Role;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

/**
 * Interface to get and set OAuth2 access tokens.
 *
 * @version $Id$
 * @since 2.15.0
 */
@Role
public interface OAuth2TokenStore
{
    /**
     * Save the oauth2 access token.
     *
     * @param configuration the client configuration to use
     * @param accessToken the access token to be saved
     * @param refreshToken the refresh token
     * @throws OAuth2Exception if an error happens
     */
    void setToken(OIDCClientConfiguration configuration, AccessToken accessToken, RefreshToken refreshToken)
        throws OAuth2Exception;

    /**
     * Retrieve the access token related to the given client configuration. Returns null if no token is found.
     *
     * @param configuration the client configuration to use
     * @return the corresponding access token, or null if no token is found
     * @throws OAuth2Exception if an error happens
     */
    AccessToken getAccessToken(OIDCClientConfiguration configuration) throws OAuth2Exception;

    /**
     * Retrieve the refresh token related to the given client configuration. Returns null if no token is found.
     *
     * @param configuration the client configuration to use
     * @return the corresponding refresh token, or null if no token is found
     * @throws OAuth2Exception if an error happens
     */
    RefreshToken getRefreshToken(OIDCClientConfiguration configuration) throws OAuth2Exception;
}
