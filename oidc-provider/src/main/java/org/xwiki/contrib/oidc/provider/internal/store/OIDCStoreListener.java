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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

/**
 * Update the stored authorization code based on events.
 * 
 * @version $Id$
 * @since 2.14.0
 */
@Component
@Named(OIDCStoreListener.NAME)
@Singleton
public class OIDCStoreListener extends AbstractEventListener
{
    /**
     * The name of this event listener (and its component hint at the same time).
     */
    public static final String NAME = "OIDCStoreListener";

    @Inject
    private Provider<OIDCStore> storeProvider;

    /**
     * The default constructor.
     */
    public OIDCStoreListener()
    {
        super(NAME, new AuthorizationCodeCreatedEvent(), new AuthorizationCodeDeletedEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (event instanceof AuthorizationCodeCreatedEvent) {
            this.storeProvider.get().authorizationSessionMap.put(((AuthorizationCodeCreatedEvent) event).getCode(),
                (AuthorizationSession) source);
        } else if (event instanceof AuthorizationCodeDeletedEvent) {
            this.storeProvider.get().authorizationSessionMap.remove(((AuthorizationCodeDeletedEvent) event).getCode());
        }
    }
}
