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
import java.util.Date;

/**
 * An OpenID Connect consent.
 * 
 * @version $Id$
 * @since 2.13.0
 */
public interface OIDCConsent
{
    /**
     * @return the identifier of the consent
     */
    String getId();

    /**
     * @return the identifier of the client
     */
    String getClientID();

    /**
     * @return the redirect associated with the consent
     */
    URI getRedirectURI();

    /**
     * @return the clear value of the access token or null if loaded from the storage (in which case the clear value is
     *         not recoverable)
     */
    String getAccessTokenValue();

    /**
     * @return the token expiration date
     */
    Date getAccessTokenExpiration();

    /**
     * @return true if the consent should be taken into account when authenticating
     */
    boolean isEnabled();
}