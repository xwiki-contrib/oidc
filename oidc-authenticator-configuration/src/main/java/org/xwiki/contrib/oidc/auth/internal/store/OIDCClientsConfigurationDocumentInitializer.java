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

import java.util.Arrays;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.AbstractMandatoryDocumentInitializer;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Initializes the OIDC Clients document in order for the {@link OIDCClientsConfigurationSource} to be able to update
 * its entries if necessary.
 *
 * @version $Id$
 * @since 2.28.0
 */
// We want this class to initialize after the OIDCClientsConfigurationClassDocumentInitializer.
@Priority(2000)
@Component
@Singleton
@Named("XWiki.OIDC.ClientsConfiguration")
public class OIDCClientsConfigurationDocumentInitializer extends AbstractMandatoryDocumentInitializer
{
    /**
     * The reference of the configuration page.
     */
    public static final LocalDocumentReference REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "ClientsConfiguration");

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public OIDCClientsConfigurationDocumentInitializer()
    {
        super(REFERENCE, "OIDC Clients Configuration");
    }

    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        boolean modified = updateDocumentFields(document, getTitle());
        // Ensure the document has an XWikiGroups object
        if (document.getXObject(OIDCClientsConfigurationClassDocumentInitializer.CLASS_REFERENCE) == null) {
            try {
                document.newXObject(OIDCClientsConfigurationClassDocumentInitializer.CLASS_REFERENCE,
                    xcontextProvider.get());
                modified = true;
            } catch (XWikiException e) {
                logger.error("Failed to initialize the OIDC Clients configuration in the wiki [{}]",
                    document.getDocumentReference().getWikiReference().getName(), e);
            }
        }
        return modified;
    }
}
