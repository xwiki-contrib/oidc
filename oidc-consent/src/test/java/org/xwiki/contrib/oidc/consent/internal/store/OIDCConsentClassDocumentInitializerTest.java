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
package org.xwiki.contrib.oidc.consent.internal.store;

import javax.inject.Named;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.oidc.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.classes.PasswordClass;
import com.xpn.xwiki.objects.meta.PasswordMetaClass;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Validate {@link OIDCConsentClassDocumentInitializer}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCConsentClassDocumentInitializerTest
{
    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    @MockComponent
    private OIDCConsentAccessTokenUpdater updater;

    @InjectMockComponents
    private OIDCConsentClassDocumentInitializer initializer;

    private XWikiDocument getClassDocument() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        return this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, xcontext.getWikiReference()), xcontext);
    }

    private PasswordClass getAccessTokenClass(XWikiDocument classDocument)
    {
        return (PasswordClass) classDocument.getXClass().getField(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN);
    }

    private XWikiDocument getClassDocumentWithAccessTokenStorage(String storageType) throws Exception
    {
        XWikiDocument classDocument = getClassDocument();
        classDocument.getXClass().addPasswordField(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN, "Access Token", 30,
            storageType);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, this.oldcore.getXWikiContext());

        return getClassDocument();
    }

    @Test
    void updateDocumentWithNewClass() throws Exception
    {
        XWikiDocument classDocument = getClassDocument();

        assertTrue(this.initializer.updateDocument(classDocument));

        assertEquals(PasswordMetaClass.HASH, getAccessTokenClass(classDocument).getStorageType());
        verify(this.updater, never()).resetNotHashedAccessTokens();
    }

    @Test
    void updateDocumentWithHashStorage() throws Exception
    {
        XWikiDocument classDocument = getClassDocumentWithAccessTokenStorage(PasswordMetaClass.HASH);

        this.initializer.updateDocument(classDocument);

        assertEquals(PasswordMetaClass.HASH, getAccessTokenClass(classDocument).getStorageType());
        verify(this.updater, never()).resetNotHashedAccessTokens();
    }

    @Test
    void updateDocumentWithClearStorage() throws Exception
    {
        XWikiDocument classDocument = getClassDocumentWithAccessTokenStorage(PasswordMetaClass.CLEAR);

        assertTrue(this.initializer.updateDocument(classDocument));

        // The storage type explicitly indicated in the class definition is applied to the existing property
        assertEquals(PasswordMetaClass.HASH, getAccessTokenClass(classDocument).getStorageType());
        // The values stored with the previous storage type are reset
        verify(this.updater).resetNotHashedAccessTokens();
    }

    @Test
    void updateDocumentWhenResetFails() throws Exception
    {
        XWikiDocument classDocument = getClassDocumentWithAccessTokenStorage(PasswordMetaClass.CLEAR);
        doThrow(new OIDCException("error")).when(this.updater).resetNotHashedAccessTokens();

        assertTrue(this.initializer.updateDocument(classDocument));

        assertEquals(PasswordMetaClass.HASH, getAccessTokenClass(classDocument).getStorageType());
        assertEquals("Failed to reset the OIDC access tokens stored with a previous configuration",
            this.logCapture.getMessage(0));
    }
}
