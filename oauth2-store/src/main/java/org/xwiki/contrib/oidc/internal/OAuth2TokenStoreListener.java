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

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.collections4.ListUtils;
import org.slf4j.Logger;
import org.xwiki.bridge.event.WikiDeletedEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.XObjectEvent;
import com.xpn.xwiki.objects.BaseObjectReference;

/**
 * Listener dedicated to invalidate the token store cache when needed.
 *
 * @version $Id$
 * @since 2.18.3
 */
@Component
@Named(OAuth2TokenStoreListener.NAME)
@Singleton
public class OAuth2TokenStoreListener extends AbstractEventListener
{
    /**
     * Name of the listener. See {@link OAuth2TokenStoreListener}
     */
    public static final String NAME = "OAuth2TokenStoreListener";

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private Logger logger;

    /**
     * The default constructor.
     */
    public OAuth2TokenStoreListener()
    {
        super(NAME, ListUtils.union(BaseObjectReference.anyEvents(NimbusOAuth2Token.CLASS_FULLNAME),
            List.of(new WikiDeletedEvent())));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {

        List<OAuth2TokenStore> oauth2TokenStores = null;
        try {
            oauth2TokenStores = getOAuth2TokenStore();
        } catch (ComponentLookupException e) {
            logger.error("Can't get instances of OAuth2TokenStore", e);
            return;
        }
        if (event instanceof XObjectEvent) {
            XWikiDocument document = (XWikiDocument) source;
            DocumentReference documentToInvalidate = document.getDocumentReference();
            for (OAuth2TokenStore store : oauth2TokenStores) {
                store.invalidateCache(documentToInvalidate);
            }
        } else if (event instanceof WikiDeletedEvent) {
            for (OAuth2TokenStore store : oauth2TokenStores) {
                store.clearCache();
            }
        }
    }

    private List<OAuth2TokenStore> getOAuth2TokenStore() throws ComponentLookupException
    {
        return componentManagerProvider.get().getInstanceList(OAuth2TokenStore.class);
    }
}
