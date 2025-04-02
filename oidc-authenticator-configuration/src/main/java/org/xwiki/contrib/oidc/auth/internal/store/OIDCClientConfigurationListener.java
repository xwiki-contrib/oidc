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

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.collections4.ListUtils;
import org.xwiki.bridge.event.WikiDeletedEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.XObjectEvent;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseObjectReference;

/**
 * @version $Id$
 * @since 17.3.0CR1
 * @since 16.10.6
 */
@Component
@Named(OIDCClientConfigurationListener.NAME)
@Singleton
public class OIDCClientConfigurationListener extends AbstractEventListener
{
    /**
     * The name of this event listener (and its component hint at the same time).
     */
    public static final String NAME = "OIDCClientConfigurationListener";

    @Inject
    private OIDCClientConfigurationCache cache;

    /**
     * The default constructor.
     */
    public OIDCClientConfigurationListener()
    {
        super(NAME, ListUtils.union(BaseObjectReference.anyEvents(OIDCClientConfiguration.CLASS_FULLNAME),
            List.of(new WikiDeletedEvent())));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (event instanceof XObjectEvent) {
            XObjectEvent objectEvent = (XObjectEvent) event;
            EntityReference reference = objectEvent.getReference();

            XWikiDocument document = (XWikiDocument) source;

            invalidate(document, reference);
            invalidate(document.getOriginalDocument(), reference);
        } else if (event instanceof WikiDeletedEvent) {
            this.cache.clear();
        }
    }

    private void invalidate(XWikiDocument document, EntityReference objectReference)
    {
        BaseObject xobject = document.getXObject(objectReference);

        if (xobject != null) {
            this.cache.invalidate(document.getStringValue(OIDCClientConfiguration.FIELD_CONFIGURATION_NAME));
        }
    }
}
