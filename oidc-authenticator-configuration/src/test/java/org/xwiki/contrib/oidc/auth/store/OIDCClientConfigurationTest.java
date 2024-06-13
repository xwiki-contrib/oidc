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
package org.xwiki.contrib.oidc.auth.store;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCClientConfigurationClassDocumentInitializer;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.junit5.mockito.InjectMockComponents;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validate {@link OIDCClientConfiguration}.
 * 
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
public class OIDCClientConfigurationTest
{
    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @InjectMockComponents
    private OIDCClientConfigurationClassDocumentInitializer classInitializer;

    private XWikiDocument document;

    private BaseObject xobject;

    private OIDCClientConfiguration configuration;

    @BeforeEach
    void beforeEach() throws XWikiException
    {
        // Initialize the configuration class
        DocumentReference configurationClassReference = new DocumentReference(OIDCClientConfiguration.CLASS_REFERENCE,
            this.oldcore.getXWikiContext().getWikiReference());
        XWikiDocument classDocument =
            this.oldcore.getSpyXWiki().getDocument(configurationClassReference, this.oldcore.getXWikiContext());
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, this.oldcore.getXWikiContext());

        // Initialize the configuration object
        this.document = this.oldcore.getSpyXWiki().getDocument(new DocumentReference("wiki", "space", "document"),
            this.oldcore.getXWikiContext());
        this.xobject =
            this.document.newXObject(OIDCClientConfiguration.CLASS_REFERENCE, this.oldcore.getXWikiContext());

        // Initialize the configuration
        this.configuration = new OIDCClientConfiguration(this.xobject);
    }

    @Test
    void getUserInfoRefreshRate()
    {
        assertNull(this.configuration.getUserInfoRefreshRate());

        this.xobject.setIntValue(OIDCClientConfiguration.FIELD_USER_INFO_REFRESH_RATE, -1);

        assertNull(this.configuration.getUserInfoRefreshRate());

        this.xobject.setIntValue(OIDCClientConfiguration.FIELD_USER_INFO_REFRESH_RATE, 0);

        assertEquals(0, this.configuration.getUserInfoRefreshRate());

        this.xobject.setIntValue(OIDCClientConfiguration.FIELD_USER_INFO_REFRESH_RATE, 42);

        assertEquals(42, this.configuration.getUserInfoRefreshRate());
    }

    @Test
    void getUserInfoSkip()
    {
        assertNull(this.configuration.getUserInfoSkip());

        this.xobject.setIntValue(OIDCClientConfiguration.FIELD_USER_INFO_SKIP, -1);

        assertNull(this.configuration.getUserInfoSkip());

        this.xobject.setIntValue(OIDCClientConfiguration.FIELD_USER_INFO_SKIP, 0);

        assertTrue(this.configuration.getUserInfoSkip());

        this.xobject.setIntValue(OIDCClientConfiguration.FIELD_USER_INFO_SKIP, 1);

        assertFalse(this.configuration.getUserInfoSkip());
    }
}
