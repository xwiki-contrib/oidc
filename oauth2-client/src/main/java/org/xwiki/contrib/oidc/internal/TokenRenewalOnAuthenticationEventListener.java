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
package org.xwiki.contrib.oidc.internal;

import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.OAuth2ClientManager;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.OAuth2Token;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.security.authentication.UserAuthenticatedEvent;
import org.xwiki.user.UserReferenceSerializer;

/**
 * Listener that will automatically attempt to renew tokens stored in user profiles upon user login.
 *
 * @version $Id$
 * @since 2.17.0
 */
@Component
@Singleton
@Named(TokenRenewalOnAuthenticationEventListener.NAME)
public class TokenRenewalOnAuthenticationEventListener extends AbstractEventListener
{
    /**
     * The listener name.
     */
    public static final String NAME = "oauth2TokenRenewalEventListener";

    @Inject
    @Named("document")
    private UserReferenceSerializer<DocumentReference> serializer;

    @Inject
    private OAuth2ClientManager clientManager;

    @Inject
    private OAuth2TokenStore tokenStore;

    @Inject
    private Logger logger;

    /**
     * Create a new listener.
     */
    public TokenRenewalOnAuthenticationEventListener()
    {
        super(NAME, new UserAuthenticatedEvent(null));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        UserAuthenticatedEvent userAuthenticatedEvent = (UserAuthenticatedEvent) event;
        DocumentReference reference = serializer.serialize(userAuthenticatedEvent.getUserReference());

        if (reference != null) {
            try {
                Set<OAuth2Token> tokens = tokenStore.getTokens(reference);

                for (OAuth2Token token : tokens) {
                    logger.debug("Attempting renewal of token [{}]", token.getReference());
                    clientManager.renew(token, false);
                }
            } catch (OAuth2Exception e) {
                logger.error("Failed to retrieve OAuth2 tokens for user [{}]", reference, e);
            }
        }
    }
}
