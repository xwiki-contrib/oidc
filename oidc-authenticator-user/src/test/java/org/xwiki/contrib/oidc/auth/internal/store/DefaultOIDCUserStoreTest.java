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

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.oidc.auth.store.OIDCUser;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link DefaultOIDCUserStore}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class DefaultOIDCUserStoreTest
{
    private static final String ISSUER = "issuer";

    private static final String SUBJECT = "subject";

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
    private QueryManager queryManager;

    @InjectMockComponents
    private OIDCUserClassDocumentInitializer classInitializer;

    @InjectMockComponents
    private DefaultOIDCUserStore store;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(OIDCUser.CLASS_REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);
    }

    private void saveDocument(String space, String name, boolean userProfile) throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();
        XWikiDocument document = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(xcontext.getWikiId(), space, name), xcontext);
        this.store.updateOIDCUser(document, ISSUER, SUBJECT);
        if (userProfile) {
            document.newXObject(this.oldcore.getSpyXWiki().getUserClass(xcontext).getDocumentReference(), xcontext);
        }
        this.oldcore.getSpyXWiki().saveDocument(document, xcontext);
    }

    private void mockSearch(String... documents) throws Exception
    {
        Query query = mock(Query.class);
        when(this.queryManager.createQuery(anyString(), anyString())).thenReturn(query);
        when(query.bindValue(anyString(), any())).thenReturn(query);
        when(query.execute()).thenReturn(Arrays.asList(documents));
    }

    private String searchDocument() throws Exception
    {
        XWikiDocument document = this.store.searchDocument(ISSUER, SUBJECT);

        return document != null ? document.getFullName() : null;
    }

    @Test
    void updateOIDCUser()
    {
        XWikiDocument document = new XWikiDocument(new DocumentReference("xwiki", "XWiki", "user"));

        assertTrue(this.store.updateOIDCUser(document, ISSUER, SUBJECT));
        assertFalse(this.store.updateOIDCUser(document, ISSUER, SUBJECT));
        assertTrue(this.store.updateOIDCUser(document, ISSUER, "other"));

        OIDCUser oidcUser = new OIDCUser(document.getXObject(OIDCUser.CLASS_REFERENCE));
        assertEquals(ISSUER, oidcUser.getIssuer());
        assertEquals("other", oidcUser.getSubject());
    }

    @Test
    void searchDocumentWhenNoneIsFound() throws Exception
    {
        mockSearch();

        assertNull(searchDocument());
    }

    @Test
    void searchDocumentWithUserProfile() throws Exception
    {
        saveDocument("XWiki", "user", true);
        mockSearch("XWiki.user");

        assertEquals("XWiki.user", searchDocument());
    }

    @Test
    void searchDocumentIgnoresInvalidDocuments() throws Exception
    {
        saveDocument("Sandbox", "SuperAdmin", true);
        saveDocument("Sandbox", "Page", false);
        mockSearch("Sandbox.SuperAdmin", "Sandbox.Page", "XWiki.deleteduser");

        assertNull(searchDocument());
        assertEquals(2, this.logCapture.size());
        assertEquals("Ignoring the OpenID Connect user object of document [xwiki:Sandbox.SuperAdmin]: its name is"
            + " reserved for the superadmin user", this.logCapture.getMessage(0));
        assertEquals("Ignoring the OpenID Connect user object of document [xwiki:Sandbox.Page]: it's not a user"
            + " profile", this.logCapture.getMessage(1));
    }

    @Test
    void searchDocumentWithSeveralUserProfiles() throws Exception
    {
        saveDocument("XWiki", "olderuser", true);
        saveDocument("XWiki", "neweruser", true);
        mockSearch("XWiki.olderuser", "XWiki.neweruser");

        // The first user profile in the search order is used
        assertEquals("XWiki.olderuser", searchDocument());
        assertEquals("Several documents are associated with the OpenID Connect identity with issuer [issuer] and"
            + " subject [subject]: [XWiki.olderuser, XWiki.neweruser]. The oldest user profile,"
            + " [xwiki:XWiki.olderuser], is used.", this.logCapture.getMessage(0));
    }
}
