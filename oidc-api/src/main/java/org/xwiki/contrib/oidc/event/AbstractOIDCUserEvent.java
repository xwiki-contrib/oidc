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
import org.xwiki.observation.event.Event;

/**
 * Base class for OpenID Connect users related events.
 * 
 * @version $Id$
 * @since 1.4
 */
public abstract class AbstractOIDCUserEvent implements Event
{
    private DocumentReference user;

    /**
     * Matches all users.
     */
    public AbstractOIDCUserEvent()
    {
    }

    /**
     * @param user the user for which the event has been sent
     */
    public AbstractOIDCUserEvent(DocumentReference user)
    {
        this.user = user;
    }

    /**
     * @return the user for which the event has been sent
     */
    public DocumentReference getUser()
    {
        return this.user;
    }

    @Override
    public boolean matches(Object otherEvent)
    {
        if (otherEvent instanceof AbstractOIDCUserEvent) {
            return getUser() == null || getUser().equals(((AbstractOIDCUserEvent) otherEvent).getUser());
        }

        return false;
    }
}
