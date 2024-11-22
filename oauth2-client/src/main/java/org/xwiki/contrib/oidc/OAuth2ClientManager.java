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

import org.xwiki.component.annotation.Role;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;

/**
 * Manager for OAuth2 clients.
 *
 * @version $Id$
 * @since 2.14.0
 */
@Role
public interface OAuth2ClientManager
{
    /**
     * Authorize a configuration.
     *
     * @param config the configuration to be authorized
     * @param redirectURI the redirect URI
     * @throws OAuth2Exception if an error happens
     */
    void authorize(OIDCClientConfiguration config, URI redirectURI) throws OAuth2Exception;
}
