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

import java.util.List;

import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.stability.Unstable;

/**
 * An OAuth2 token.
 *
 * @version $Id$
 * @since 2.16.0
 */
@Unstable
public interface OAuth2Token
{
    /**
     * @return the token client configuration
     */
    OIDCClientConfiguration getConfiguration();

    /**
     * @return the token reference in XWiki
     */
    ObjectReference getReference();

    /**
     * @return the access token value
     */
    String getAccessToken();

    /**
     * @return the refresh token value
     */
    String getRefreshToken();

    /**
     * @return the token type
     */
    String getType();

    /**
     * @return the token expiration timestamp
     */
    long getExpiresAt();

    /**
     * @return the token scopes
     */
    List<String> getScopes();
}
