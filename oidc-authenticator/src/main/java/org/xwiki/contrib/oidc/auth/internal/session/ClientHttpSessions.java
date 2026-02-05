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

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.xwiki.component.annotation.Component;

import com.nimbusds.oauth2.sdk.id.Subject;

/**
 * A helper to access all sessions.
 *
 * @version $Id: c60ed9b2455052c9b46af99f25f8ca47120c6e9e $
 * @since 2.4.0
 */
@Component(roles = ClientHttpSessions.class)
@Singleton
public class ClientHttpSessions
{
    private final class ProviderSession
    {
        private HttpSession httpSession;

        private Subject subject;

        private ProviderSession(HttpSession httpSession)
        {
            this.httpSession = httpSession;
        }
    }

    private final Map<HttpSession, ProviderSession> sessions = new IdentityHashMap<>();

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    /**
     * @param session the session that just been authenticated
     * @param subject the authenticated subject
     */
    public void onLogin(HttpSession session, Subject subject)
    {
        this.lock.writeLock().lock();

        try {
            ProviderSession providerSession = this.sessions.get(session);

            if (providerSession == null) {
                providerSession = new ProviderSession(session);

                this.sessions.put(session, providerSession);
            }

            providerSession.subject = subject;
        } finally {
            this.lock.writeLock().unlock();
        }
    }

    /**
     * @param session the session that just been destroyed
     */
    public void onSessionDestroyed(HttpSession session)
    {
        this.lock.writeLock().lock();

        try {
            this.sessions.remove(session);
        } finally {
            this.lock.writeLock().unlock();
        }
    }

    /**
     * @param subject the subject of the sessions to logout
     */
    public void logout(Subject subject)
    {
        this.lock.readLock().lock();

        List<HttpSession> sessionToLogout = null;

        try {

            for (Map.Entry<HttpSession, ProviderSession> entry : this.sessions.entrySet()) {
                if (subject.equals(entry.getValue().subject)) {
                    if (sessionToLogout == null) {
                        sessionToLogout = new ArrayList<>();
                    }
                    sessionToLogout.add(entry.getKey());
                }
            }
        } finally {
            this.lock.readLock().unlock();
        }

        if (sessionToLogout != null) {
            sessionToLogout.forEach(this::logout);
        }
    }

    /**
     * @param session the session to logout
     */
    public void logout(HttpSession session)
    {
        this.lock.writeLock().lock();

        try {
            try {
                // Destroy the whole session, if any, so that any private data stored in the session won't be accessible
                // by the next user on the same computer
                session.invalidate();
            } catch (IllegalStateException e) {
                // The session is already invalidated, nothing to do
            }

            // Forget the session
            this.sessions.remove(session);
        } finally {
            this.lock.writeLock().unlock();
        }
    }
}
