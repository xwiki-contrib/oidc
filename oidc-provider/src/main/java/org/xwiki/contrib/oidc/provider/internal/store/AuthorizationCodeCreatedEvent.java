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
package org.xwiki.contrib.oidc.provider.internal.store;

import com.nimbusds.oauth2.sdk.AuthorizationCode;

/**
 * Event sent when a new authorization code is to be stored.
 * <p>
 * The event also send the following parameters:
 * </p>
 * <ul>
 * <li>source: the {@link AuthorizationSession} associated to the authorization code.</li>
 * </ul>
 * 
 * @version $Id$
 * @since 2.14.0
 */
public class AuthorizationCodeCreatedEvent extends AbstractAuthorizationCodeEvent
{
    private static final long serialVersionUID = 1L;

    /**
     * Match any {@link AuthorizationCodeCreatedEvent}.
     */
    public AuthorizationCodeCreatedEvent()
    {
        super();
    }

    /**
     * @param code the code
     */
    public AuthorizationCodeCreatedEvent(AuthorizationCode code)
    {
        super(code);
    }
}
