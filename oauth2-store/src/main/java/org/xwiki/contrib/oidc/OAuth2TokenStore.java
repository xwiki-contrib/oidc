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

import java.util.Set;

import org.xwiki.component.annotation.Role;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.stability.Unstable;

/**
 * Interface to get and set OAuth2 access tokens.
 *
 * @version $Id$
 * @since 2.15.0
 */
@Role
@Unstable
public interface OAuth2TokenStore
{
    /**
     * Save the given token.
     *
     * @param token the token to save
     * @throws OAuth2Exception if an error happens
     * @since 2.16.0
     */
    void saveToken(OAuth2Token token) throws OAuth2Exception;

    /**
     * Retrieve the OAuth2 token stored in XWiki, related to the given client configuration. Returns null if no token
     * is found.
     *
     * @param configuration the client configuration to use
     * @return the corresponding token, or null if no token is found
     * @throws OAuth2Exception if an error happens
     * @since 2.16.0
     */
    OAuth2Token getToken(OIDCClientConfiguration configuration) throws OAuth2Exception;

    /**
     * Delete the given token.
     *
     * @param token the OAuth2 token to delete
     * @throws OAuth2Exception if an error happens
     * @since 2.16.0
     */
    void deleteToken(OAuth2Token token) throws OAuth2Exception;

    /**
     * Delete the OAuth2 access token associated with this configuration.
     *
     * @param configuration the configuration to use
     * @throws OAuth2Exception if an error happens
     * @since 2.16.0
     */
    void deleteToken(OIDCClientConfiguration configuration) throws OAuth2Exception;

    /**
     * Provide the reference to be used for storing oauth2 tokens for the given configuration.
     *
     * @param configuration the configuration to use
     * @return an object reference that should be used to store the token
     * @throws OAuth2Exception if an error happens
     * @since 2.16.0
     */
    ObjectReference getConfiguredObjectReference(OIDCClientConfiguration configuration) throws OAuth2Exception;

    /**
     * Get a set of tokens that the given document contains.
     *
     * @param documentReference the reference to the document from which tokens should be extracted
     * @return a set of tokens found in the document
     * @throws OAuth2Exception if an error happens
     * @since 2.17.0
     */
    Set<OAuth2Token> getTokens(DocumentReference documentReference) throws OAuth2Exception;
}
