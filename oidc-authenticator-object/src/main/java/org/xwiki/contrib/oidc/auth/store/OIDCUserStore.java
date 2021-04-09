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
 * Helper to manager OpenID Connect profiles XClass and XObject.
 * 
 * @version $Id: c68c46c340eb3dd4988644e71d45541e9c1f25eb $
 * @since 1.25
 */
@Role
public interface OIDCUserStore
{
    /**
     * Add or update OIDC metadata in the user profile.
     * 
     * @param userDocument the document in which the OIDC user is stored
     * @param issuer the issuer or the OIDC user
     * @param subject the subject of the OIDC user
     * @return true if the document was modified
     */
    boolean updateOIDCUser(XWikiDocument userDocument, String issuer, String subject);

    /**
     * Search in the existing XWiki user if one is already associated with the passed OIDC user.
     * 
     * @param issuer the
     * @param subject the subject of the OIDC user
     * @return the document of the user profile which already contains this OIDC user
     * @throws XWikiException when failing the get the document
     * @throws QueryException when failing to search for the document
     */
    XWikiDocument searchDocument(String issuer, String subject) throws XWikiException, QueryException;
}
