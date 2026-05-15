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

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.AbstractMandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Inject an entry point of the OIDC provider in the administration.
 * 
 * @version $Id: 95fc9723aa88cb92d0626c5fadbff1bfe61b3f58 $
 * @since 2.21.0
 */
@Component
@Named(OIDCProviderAdminInitializer.REFERENCE_STRING)
@Singleton
public class OIDCProviderAdminInitializer extends AbstractMandatoryDocumentInitializer
{
    /**
     * The name of the mandatory document.
     */
    public static final String DOCUMENT_NAME = "Administration";

    /**
     * The local reference of the document.
     */
    public static final LocalDocumentReference REFERENCE =
        new LocalDocumentReference(DOCUMENT_NAME, OIDCProviderStore.REFERENCE_SPACE);

    /**
     * The local reference of the document as String.
     */
    public static final String REFERENCE_STRING = OIDCProviderStore.REFERENCE_PREFIX + DOCUMENT_NAME;

    private static final LocalDocumentReference CONFIGURABLE_CLASS_REFERENCE_STRING =
        new LocalDocumentReference("ConfigurableClass", XWiki.SYSTEM_SPACE_REFERENCE);

    /**
     * Used to access the XWiki model.
     */
    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public OIDCProviderAdminInitializer()
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

        // Set a ConfigurableClass object to make it appear in the administration
        BaseObject configurableObject = document.getXObject(CONFIGURABLE_CLASS_REFERENCE_STRING);

        // Assume the object is correct if it already exists
        if (configurableObject == null) {
            try {
                configurableObject =
                    document.newXObject(CONFIGURABLE_CLASS_REFERENCE_STRING, this.contextProvider.get());

                configurableObject.setLargeStringValue("codeToExecute",
                    "{{template name=\"oidc/provider/administration.vm\"/}}");
                configurableObject.setStringValue("displayInCategory", "usersgroups");
                configurableObject.setStringValue("displayInSection", "OpenID Connect");
                configurableObject.setStringValue("scope", "WIKI");

                needsUpdate = true;
            } catch (Exception e) {
                this.logger.error("Failed to initialize the OIDC provider administration page", e);
            }
        }

        return needsUpdate;
    }
}
