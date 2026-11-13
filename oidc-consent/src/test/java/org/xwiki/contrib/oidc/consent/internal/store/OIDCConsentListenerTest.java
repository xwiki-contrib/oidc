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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.event.UserCreatingDocumentEvent;
import com.xpn.xwiki.internal.event.UserUpdatingDocumentEvent;
import com.xpn.xwiki.internal.filter.XWikiDocumentFilterUtils;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCConsentListener}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCConsentListenerTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    private static final DocumentReference AUTHOR_REFERENCE = new DocumentReference("xwiki", "XWiki", "Author");

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

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
    private AuthorizationManager authorization;

    @InjectMockComponents
    private OIDCConsentClassDocumentInitializer classInitializer;

    @InjectMockComponents
    private OIDCConsentListener listener;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);
    }

    private void setProgrammingRight(boolean allowed)
    {
        when(this.authorization.hasAccess(Right.PROGRAM, AUTHOR_REFERENCE, null)).thenReturn(allowed);
    }

    /**
     * @return a document with a new consent and a new original document without any consent
     */
    private XWikiDocument createDocumentWithNewConsent() throws Exception
    {
        XWikiDocument document = new XWikiDocument(USER_REFERENCE);
        document.setOriginalDocument(new XWikiDocument(USER_REFERENCE));
        document.newXObject(BaseObjectOIDCConsent.REFERENCE, this.oldcore.getXWikiContext())
            .setStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID, "client");

        return document;
    }

    /**
     * @return a document with a modified consent, the original document holding the consent before modification
     */
    private XWikiDocument createDocumentWithModifiedConsent() throws Exception
    {
        XWikiDocument originalDocument = new XWikiDocument(USER_REFERENCE);
        originalDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, this.oldcore.getXWikiContext())
            .setStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID, "client");

        XWikiDocument document = originalDocument.clone();
        document.setOriginalDocument(originalDocument);
        document.getXObject(BaseObjectOIDCConsent.REFERENCE).setStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID,
            "other");

        return document;
    }

    @Test
    void newConsentWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument document = createDocumentWithNewConsent();

        this.listener.onEvent(new UserCreatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        assertNull(document.getXObject(BaseObjectOIDCConsent.REFERENCE));
        assertTrue(this.logCapture.getMessage(0).startsWith("A not allowed modification was requested on OIDC consent"),
            this.logCapture.getMessage(0));
    }

    @Test
    void newConsentWithProgrammingRight() throws Exception
    {
        setProgrammingRight(true);
        XWikiDocument document = createDocumentWithNewConsent();

        this.listener.onEvent(new UserCreatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        assertNotNull(document.getXObject(BaseObjectOIDCConsent.REFERENCE));
    }

    @Test
    void modifiedConsentWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument document = createDocumentWithModifiedConsent();

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        // The modification is reverted
        assertEquals("client",
            document.getXObject(BaseObjectOIDCConsent.REFERENCE).getStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID));
        assertTrue(this.logCapture.getMessage(0).startsWith("A not allowed modification was requested on OIDC consent"),
            this.logCapture.getMessage(0));
    }

    @Test
    void modifiedConsentWithProgrammingRight() throws Exception
    {
        setProgrammingRight(true);
        XWikiDocument document = createDocumentWithModifiedConsent();

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        assertEquals("other",
            document.getXObject(BaseObjectOIDCConsent.REFERENCE).getStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID));
    }

    @Test
    void unmodifiedConsentWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument originalDocument = new XWikiDocument(USER_REFERENCE);
        originalDocument.newXObject(BaseObjectOIDCConsent.REFERENCE, this.oldcore.getXWikiContext())
            .setStringValue(BaseObjectOIDCConsent.FIELD_CLIENTID, "client");
        XWikiDocument document = originalDocument.clone();
        document.setOriginalDocument(originalDocument);

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        // Nothing to revert
        assertNotNull(document.getXObject(BaseObjectOIDCConsent.REFERENCE));
        assertEquals(0, this.logCapture.size());
    }
}
