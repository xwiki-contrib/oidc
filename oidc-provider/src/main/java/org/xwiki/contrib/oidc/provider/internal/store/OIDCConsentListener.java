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

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
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
 * A listener in charge of protection against unlawful modification of tokens.
 * 
 * @version $Id$
 * @since 2.13.0
 */
@Component
@Named(OIDCConsentListener.NAME)
@Singleton
public class OIDCConsentListener extends AbstractEventListener
{
    /**
     * The name of this event listener (and its component hint at the same time).
     */
    public static final String NAME = "org.xwiki.contrib.oidc.provider.internal.store.OIDCConsentListener";

    @Inject
    private Provider<AuthorizationManager> authorization;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public OIDCConsentListener()
    {
        super(NAME, new UserCreatingDocumentEvent(), new UserUpdatingDocumentEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // Cancel any creation or modification of an OIDC consent xobject (deletes are not going to cause
        // security problems) done without going through the OIDC API
        XWikiDocument document = (XWikiDocument) source;
        XWikiDocument previousDocument = document.getOriginalDocument();
        for (BaseObject consent : document.getXObjects(BaseObjectOIDCConsent.REFERENCE)) {
            if (consent != null) {
                BaseObjectReference consentReference = consent.getReference();
                BaseObject previousConsent = previousDocument.getXObject(consentReference);
                if (previousConsent == null) {
                    if (!isAllowed((UserEvent) event)) {
                        // Canceling the new xobject
                        document.removeXObject(consent);

                        logNotAllowed(consentReference);
                    }
                } else if (!previousConsent.equals(consent)) {
                    if (!isAllowed((UserEvent) event)) {
                        // Canceling the xobject modification
                        consent.apply(previousConsent, true);

                        logNotAllowed(consentReference);
                    }
                }
            }
        }
    }

    private void logNotAllowed(BaseObjectReference consentReference)
    {
        this.logger.warn("A not allwoed modification was requested on OIDC consent object [{}] and was reverted.",
            consentReference);
    }

    private boolean isAllowed(UserEvent event)
    {
        return this.authorization.get().hasAccess(Right.PROGRAM, event.getUserReference(), null);
    }
}
