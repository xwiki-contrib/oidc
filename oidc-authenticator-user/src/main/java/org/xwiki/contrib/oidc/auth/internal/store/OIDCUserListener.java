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
package org.xwiki.contrib.oidc.auth.internal.store;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCUser;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.UserCreatingDocumentEvent;
import com.xpn.xwiki.internal.event.UserEvent;
import com.xpn.xwiki.internal.event.UserUpdatingDocumentEvent;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseObjectReference;

/**
 * A listener in charge of protecting the OpenID Connect user objects against modifications made by users: the issuer
 * and subject they contain decide which account an OpenID Connect identity is authenticated as. The authenticator
 * itself is not impacted since it does not save the user profile on behalf of a user.
 * 
 * @version $Id$
 * @since 2.31.0
 */
@Component
@Named(OIDCUserListener.NAME)
@Singleton
public class OIDCUserListener extends AbstractEventListener
{
    /**
     * The name of this event listener (and its component hint at the same time).
     */
    public static final String NAME = "org.xwiki.contrib.oidc.auth.internal.store.OIDCUserListener";

    @Inject
    private Provider<AuthorizationManager> authorization;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public OIDCUserListener()
    {
        super(NAME, new UserCreatingDocumentEvent(), new UserUpdatingDocumentEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // Cancel any creation or modification of an OIDC user xobject (deletes are not going to cause security
        // problems) done by a user without programming right
        XWikiDocument document = (XWikiDocument) source;
        XWikiDocument previousDocument = document.getOriginalDocument();
        for (BaseObject oidcUser : document.getXObjects(OIDCUser.CLASS_REFERENCE)) {
            if (oidcUser != null) {
                BaseObjectReference oidcUserReference = oidcUser.getReference();
                BaseObject previousOIDCUser =
                    previousDocument != null ? previousDocument.getXObject(oidcUserReference) : null;
                if (previousOIDCUser == null) {
                    if (!isAllowed((UserEvent) event)) {
                        // Canceling the new xobject
                        document.removeXObject(oidcUser);

                        logNotAllowed(oidcUserReference);
                    }
                } else if (!previousOIDCUser.equals(oidcUser) && !isAllowed((UserEvent) event)) {
                    // Canceling the xobject modification
                    oidcUser.apply(previousOIDCUser, true);

                    logNotAllowed(oidcUserReference);
                }
            }
        }
    }

    private void logNotAllowed(BaseObjectReference oidcUserReference)
    {
        this.logger.warn("A not allowed modification was requested on OIDC user object [{}] and was reverted.",
            oidcUserReference);
    }

    private boolean isAllowed(UserEvent event)
    {
        return this.authorization.get().hasAccess(Right.PROGRAM, event.getUserReference(), null);
    }
}
