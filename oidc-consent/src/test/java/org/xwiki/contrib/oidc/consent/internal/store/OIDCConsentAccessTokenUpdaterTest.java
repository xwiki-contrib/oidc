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

import java.util.Date;
import java.util.List;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.oidc.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.filter.XWikiDocumentFilterUtils;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCConsentAccessTokenUpdater}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCConsentAccessTokenUpdaterTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.INFO);

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    // Used when an xobject is serialized as part of an error message
    @MockComponent
    private XWikiDocumentFilterUtils filterUtils;

    @MockComponent
    private QueryManager queryManager;

    @InjectMockComponents
    private OIDCConsentClassDocumentInitializer classInitializer;

    @InjectMockComponents
    private OIDCConsentAccessTokenUpdater updater;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        // Make sure the consent class exist since creating a consent requires it
        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);

        // A user with two consents
        XWikiDocument userDocument = new XWikiDocument(USER_REFERENCE);
        userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        userDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, xcontext);
        this.oldcore.getSpyXWiki().saveDocument(userDocument, xcontext);
    }

    private XWikiDocument getUserDocument() throws Exception
    {
        return this.oldcore.getSpyXWiki().getDocument(USER_REFERENCE, this.oldcore.getXWikiContext());
    }

    private BaseObject getConsentObject(int number) throws Exception
    {
        return getUserDocument().getXObject(BaseObjectOIDCConsent.REFERENCE, number);
    }

    private Query mockQuery(String... documents) throws Exception
    {
        Query query = mock(Query.class);
        when(this.queryManager.<String>createQuery(anyString(), eq(Query.HQL))).thenReturn(query);
        when(query.bindValue(anyString(), any())).thenReturn(query);
        when(query.<String>execute()).thenReturn(List.of(documents));

        return query;
    }

    @Test
    void resetNotHashedAccessTokens() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        XWikiDocument userDocument = getUserDocument().clone();
        // A consent with a token stored according to the class definition
        new BaseObjectOIDCConsent("id", userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 0), xcontext)
            .setAccessToken(XWikiBearerAccessToken.create("xwiki:XWiki.User/0"));
        // A consent with a token stored with a different storage type
        BaseObject otherConsent = userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 1);
        otherConsent.setStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN, "notahash");
        otherConsent.setDateValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN_EXPIRE, new Date(42));
        this.oldcore.getSpyXWiki().saveDocument(userDocument, xcontext);
        String hashedValue = getConsentObject(0).getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN);

        Query query = mockQuery("XWiki.User");

        this.updater.resetNotHashedAccessTokens();

        verify(query).bindValue("className", BaseObjectOIDCConsent.REFERENCE_STRING);
        // The token stored according to the class definition is kept
        assertEquals(hashedValue, getConsentObject(0).getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN));
        // The other one is reset, but the consent itself is kept
        assertNotNull(getConsentObject(1));
        assertEquals("", getConsentObject(1).getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN));
        assertNull(getConsentObject(1).getDateValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN_EXPIRE));

        assertEquals("Checking the OIDC access tokens stored in [1] documents of wiki [xwiki]",
            this.logCapture.getMessage(0));
        assertEquals("[1/1] documents checked", this.logCapture.getMessage(1));
        assertEquals("[1] OIDC access tokens have been reset in [1] documents of wiki [xwiki] ([0] failures)",
            this.logCapture.getMessage(2));
    }

    @Test
    void resetNotHashedAccessTokensWhenNothingToReset() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        XWikiDocument userDocument = getUserDocument().clone();
        new BaseObjectOIDCConsent("id", userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 0), xcontext)
            .setAccessToken(XWikiBearerAccessToken.create("xwiki:XWiki.User/0"));
        this.oldcore.getSpyXWiki().saveDocument(userDocument, xcontext);
        String version = getUserDocument().getVersion();

        mockQuery("XWiki.User");

        this.updater.resetNotHashedAccessTokens();

        // Nothing to reset, so nothing saved
        assertEquals(version, getUserDocument().getVersion());

        assertEquals("Checking the OIDC access tokens stored in [1] documents of wiki [xwiki]",
            this.logCapture.getMessage(0));
        assertEquals("[1/1] documents checked", this.logCapture.getMessage(1));
        assertEquals("[0] OIDC access tokens have been reset in [0] documents of wiki [xwiki] ([0] failures)",
            this.logCapture.getMessage(2));
    }

    @Test
    void resetNotHashedAccessTokensWhenADocumentFails() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        XWikiDocument userDocument = getUserDocument().clone();
        userDocument.getXObject(BaseObjectOIDCConsent.REFERENCE, 0)
            .setStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN, "notahash");
        this.oldcore.getSpyXWiki().saveDocument(userDocument, xcontext);

        DocumentReference brokenReference = new DocumentReference("xwiki", "XWiki", "Broken");
        doThrow(new XWikiException()).when(this.oldcore.getSpyXWiki()).getDocument(eq(brokenReference),
            any(XWikiContext.class));

        mockQuery("XWiki.Broken", "XWiki.User");

        this.updater.resetNotHashedAccessTokens();

        // The failure on the first document does not prevent handling the next one
        assertEquals("", getConsentObject(0).getStringValue(BaseObjectOIDCConsent.FIELD_ACCESSTOKEN));

        assertEquals("Checking the OIDC access tokens stored in [2] documents of wiki [xwiki]",
            this.logCapture.getMessage(0));
        assertEquals("Failed to reset the OIDC access tokens in document [xwiki:XWiki.Broken]",
            this.logCapture.getMessage(1));
        assertEquals("[2/2] documents checked", this.logCapture.getMessage(2));
        assertEquals("[1] OIDC access tokens have been reset in [1] documents of wiki [xwiki] ([1] failures)",
            this.logCapture.getMessage(3));
    }

    @Test
    void resetNotHashedAccessTokensWhenQueryFails() throws Exception
    {
        when(this.queryManager.createQuery(anyString(), eq(Query.HQL)))
            .thenThrow(new QueryException("error", null, null));

        OIDCException exception =
            assertThrows(OIDCException.class, () -> this.updater.resetNotHashedAccessTokens());

        assertEquals("Failed to search the documents containing consents", exception.getMessage());
    }
}
