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
package org.xwiki.contrib.oidc.auth.store;

import org.xwiki.component.annotation.Role;
import org.xwiki.query.QueryException;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Helper to manager OpenID Connect client configuration XObjects.
 *
 * @version $Id$
 * @since 1.30
 */
@Role
public interface OIDCClientConfigurationStore
{
    /**
     * Search for a document having an object corresponding to the given OIDC client configuration name.
     *
     * @param name the name of the OIDC configuration to look for
     * @return the document found. Null if no document exist.
     * @throws XWikiException when failing the get the document
     * @throws QueryException when failing to search for the document
     */
    XWikiDocument getOIDCClientConfigurationDocument(String name) throws XWikiException, QueryException;

    /**
     * Loads the client configuration corresponding to the provided configuration name.
     *
     * @param name the name of the OIDC configuration to look for
     * @return the configuration found or null if no configuration exist
     * @throws XWikiException when failing the get the document containing the configuration
     * @throws QueryException when failing to search for the configuration
     */
    OIDCClientConfiguration getOIDCClientConfiguration(String name) throws XWikiException, QueryException;
}
