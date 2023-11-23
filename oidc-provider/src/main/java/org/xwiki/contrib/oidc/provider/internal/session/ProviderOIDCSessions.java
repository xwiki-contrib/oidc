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
package org.xwiki.contrib.oidc.provider.internal.session;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Singleton;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.xwiki.component.annotation.Component;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;

/**
 * A helper to manipulate user's sessions.
 *
 * @version $Id: c60ed9b2455052c9b46af99f25f8ca47120c6e9e $
 * @since 2.4.0
 */
@Component(roles = ProviderOIDCSessions.class)
@Singleton
public class ProviderOIDCSessions
{
    /**
     * A session.
     * 
     * @version $Id$
     */
    public final class ProviderOIDCSession
    {
        private final Subject subject;

        private final ClientID clientID;

        private ProviderOIDCSession(Subject subject, ClientID clientID)
        {
            this.subject = subject;
            this.clientID = clientID;
        }

        /**
         * @return the subject
         */
        public Subject getSubject()
        {
            return this.subject;
        }

        /**
         * @return the client identifier
         */
        public ClientID getClientID()
        {
            return this.clientID;
        }

        @Override
        public int hashCode()
        {
            HashCodeBuilder builder = new HashCodeBuilder();

            builder.append(this.subject);
            builder.append(this.clientID);

            return builder.build();
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj instanceof ProviderOIDCSession) {
                if (obj == this) {
                    return true;
                }

                ProviderOIDCSession otherProviderOIDCSession = (ProviderOIDCSession) obj;

                EqualsBuilder builder = new EqualsBuilder();

                builder.append(this.subject, otherProviderOIDCSession.subject);
                builder.append(this.clientID, otherProviderOIDCSession.clientID);

                return builder.build();
            }

            return false;
        }
    }

    private final Map<Subject, Set<ProviderOIDCSession>> sessions = new ConcurrentHashMap<>();

    /**
     * @param subject the user identifier
     * @param clientID the client identifier
     */
    public void addSession(Subject subject, ClientID clientID)
    {
        Set<ProviderOIDCSession> subjectSessions =
            this.sessions.computeIfAbsent(subject, s -> ConcurrentHashMap.newKeySet());

        subjectSessions.add(new ProviderOIDCSession(subject, clientID));
    }

    /**
     * @param subject the user identifier
     * @return the user's sessions
     */
    public Set<ProviderOIDCSession> removeSessions(Subject subject)
    {
        return this.sessions.remove(subject);
    }
}
