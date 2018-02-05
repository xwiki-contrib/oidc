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
package org.xwiki.contrib.oidc.event;

import org.xwiki.model.reference.DocumentReference;

/**
 * Event sent when a user document update from OpenID Connect UserInfo is about to be applied.
 * <p>
 * The event also send the following parameters:
 * </p>
 * <ul>
 * <li>source: the com.xpn.xwiki.doc.XWikiDocument instance to modify</li>
 * <li>data: an {@link OIDCUserEventData} instance containing various informations about the user and its provider</li>
 * </ul>
 * 
 * @version $Id$
 * @since 1.4
 */
public class OIDCUserUpdating extends AbstractOIDCUserEvent
{
    /**
     * Matches all users.
     */
    public OIDCUserUpdating()
    {
    }

    /**
     * @param user the user for which the event has been sent
     */
    public OIDCUserUpdating(DocumentReference user)
    {
        super(user);
    }
}
