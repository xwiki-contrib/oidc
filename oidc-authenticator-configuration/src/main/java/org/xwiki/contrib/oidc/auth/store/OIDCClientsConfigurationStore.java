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

/**
 * Give access to the wiki configuration shared by all the OpenID Connect clients (e.g. the default client
 * configuration to use).
 *
 * @version $Id$
 * @since 2.28.0
 */
@Role
public interface OIDCClientsConfigurationStore
{
    /**
     * @return the name of the cookie in which the name of the OIDC client configuration to use is stored, or
     *     {@code null} if not set in the current wiki
     */
    String getClientConfigurationCookie();

    /**
     * @return the name of the default OIDC client configuration, or {@code null} if not set in the current wiki
     */
    String getDefaultClientConfiguration();
}
