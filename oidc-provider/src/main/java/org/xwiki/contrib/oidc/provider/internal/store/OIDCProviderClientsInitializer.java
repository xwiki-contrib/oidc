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
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.AbstractMandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.mandatory.XWikiRightsDocumentInitializer;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Make sure the document in charge of storing the registered clients exist and has the right content.
 * 
 * @version $Id: 95fc9723aa88cb92d0626c5fadbff1bfe61b3f58 $
 * @since 2.21.0
 */
@Component
@Named(OIDCProviderClientsInitializer.REFERENCE_STRING)
@Singleton
public class OIDCProviderClientsInitializer extends AbstractMandatoryDocumentInitializer
{
    /**
     * The name of the mandatory document.
     */
    public static final String DOCUMENT_NAME = "Clients";

    /**
     * The local reference of the document.
     */
    public static final LocalDocumentReference REFERENCE =
        new LocalDocumentReference(DOCUMENT_NAME, OIDCProviderStore.REFERENCE_SPACE);

    /**
     * The local reference of the document as String.
     */
    public static final String REFERENCE_STRING = OIDCProviderStore.REFERENCE_PREFIX + DOCUMENT_NAME;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public OIDCProviderClientsInitializer()
    {
        super(REFERENCE);
    }

    @Override
    public boolean isMainWikiOnly()
    {
        // Initialize it only for the main wiki.
        return true;
    }

    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        boolean needsUpdate = super.updateDocument(document);

        if (document.isNew()) {
            document.setTitle("OIDC Connection Clients");
            document.setContent("{{translation key=\"oidc.provider.clients.description\"/}}");
            document.setHidden(true);

            try {
                // Make sure only wiki administrators can access it
                BaseObject rightObject =
                    document.newXObject(XWikiRightsDocumentInitializer.CLASS_REFERENCE, this.contextProvider.get());
                rightObject.setStringValue("groups", "XWiki.XWikiAdminGroup");
                rightObject.setStringValue("allow", "view");

                needsUpdate = true;
            } catch (XWikiException e) {
                this.logger.error("Faied to initialize main wiki descriptor", e);
            }
        }

        return needsUpdate;
    }
}
