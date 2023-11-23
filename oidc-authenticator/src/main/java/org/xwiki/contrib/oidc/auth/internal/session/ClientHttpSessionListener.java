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
package org.xwiki.contrib.oidc.auth.internal.session;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.xwiki.component.annotation.Component;
import org.xwiki.container.servlet.events.SessionDestroyedEvent;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

/**
 * Update {@link ClientHttpSessions}.
 * 
 * @version $Id$
 * @since 2.4.0
 */
@Component
@Named(ClientHttpSessionListener.NAME)
@Singleton
public class ClientHttpSessionListener extends AbstractEventListener
{
    /**
     * The name of the listener.
     */
    public static final String NAME = "org.xwiki.contrib.oidc.auth.internal.session.ClientHttpSessionListener";

    @Inject
    private ClientHttpSessions sessions;

    /**
     * The default constructor.
     */
    public ClientHttpSessionListener()
    {
        super(NAME, new SessionDestroyedEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        this.sessions.onSessionDestroyed((HttpSession) source);
    }
}
