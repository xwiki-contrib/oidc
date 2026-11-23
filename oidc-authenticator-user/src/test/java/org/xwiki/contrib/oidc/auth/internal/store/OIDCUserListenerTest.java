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

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.oidc.auth.store.OIDCUser;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCUserListener}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCUserListenerTest
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
    private OIDCUserClassDocumentInitializer classInitializer;

    @InjectMockComponents
    private OIDCUserListener listener;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(OIDCUser.CLASS_REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);
    }

    private static String notAllowedMessage(int objectNumber)
    {
        return "A not allowed modification was requested on OIDC user object [Object xwiki:XWiki.User^"
            + "XWiki.OIDC.UserClass[" + objectNumber + "]] and was reverted.";
    }

    private void setProgrammingRight(boolean allowed)
    {
        when(this.authorization.hasAccess(Right.PROGRAM, AUTHOR_REFERENCE, null)).thenReturn(allowed);
    }

    private OIDCUser newOIDCUser(XWikiDocument document, String subject) throws Exception
    {
        OIDCUser oidcUser =
            new OIDCUser(document.newXObject(OIDCUser.CLASS_REFERENCE, this.oldcore.getXWikiContext()));
        oidcUser.setIssuer("issuer");
        oidcUser.setSubject(subject);

        return oidcUser;
    }

    /**
     * @return a document with a new OIDC user object and an original document without any
     */
    private XWikiDocument createDocumentWithNewOIDCUser() throws Exception
    {
        XWikiDocument document = new XWikiDocument(USER_REFERENCE);
        document.setOriginalDocument(new XWikiDocument(USER_REFERENCE));
        newOIDCUser(document, "subject");

        return document;
    }

    /**
     * @return a document with a modified OIDC user object, the original document holding the object before
     *         modification
     */
    private XWikiDocument createDocumentWithModifiedOIDCUser() throws Exception
    {
        XWikiDocument originalDocument = new XWikiDocument(USER_REFERENCE);
        newOIDCUser(originalDocument, "subject");

        XWikiDocument document = originalDocument.clone();
        document.setOriginalDocument(originalDocument);
        new OIDCUser(document.getXObject(OIDCUser.CLASS_REFERENCE)).setSubject("other");

        return document;
    }

    private String getSubject(XWikiDocument document)
    {
        return new OIDCUser(document.getXObject(OIDCUser.CLASS_REFERENCE)).getSubject();
    }

    @Test
    void newOIDCUserWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument document = createDocumentWithNewOIDCUser();

        this.listener.onEvent(new UserCreatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        assertNull(document.getXObject(OIDCUser.CLASS_REFERENCE));
        assertEquals(notAllowedMessage(0), this.logCapture.getMessage(0));
    }

    @Test
    void newOIDCUserWithProgrammingRight() throws Exception
    {
        setProgrammingRight(true);
        XWikiDocument document = createDocumentWithNewOIDCUser();

        this.listener.onEvent(new UserCreatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        assertEquals("subject", getSubject(document));
    }

    @Test
    void additionalOIDCUserWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument originalDocument = new XWikiDocument(USER_REFERENCE);
        newOIDCUser(originalDocument, "subject");
        XWikiDocument document = originalDocument.clone();
        document.setOriginalDocument(originalDocument);
        newOIDCUser(document, "other");

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        // Only the existing object remains
        assertEquals(1, document.getXObjects(OIDCUser.CLASS_REFERENCE).stream().filter(o -> o != null).count());
        assertEquals("subject", getSubject(document));
        assertEquals(notAllowedMessage(1), this.logCapture.getMessage(0));
    }

    @Test
    void modifiedOIDCUserWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument document = createDocumentWithModifiedOIDCUser();

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        // The modification is reverted
        assertEquals("subject", getSubject(document));
        assertEquals(notAllowedMessage(0), this.logCapture.getMessage(0));
    }

    @Test
    void modifiedOIDCUserWithProgrammingRight() throws Exception
    {
        setProgrammingRight(true);
        XWikiDocument document = createDocumentWithModifiedOIDCUser();

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        assertEquals("other", getSubject(document));
    }

    @Test
    void unmodifiedOIDCUserWithoutProgrammingRight() throws Exception
    {
        setProgrammingRight(false);
        XWikiDocument originalDocument = new XWikiDocument(USER_REFERENCE);
        newOIDCUser(originalDocument, "subject");
        XWikiDocument document = originalDocument.clone();
        document.setOriginalDocument(originalDocument);

        this.listener.onEvent(new UserUpdatingDocumentEvent(AUTHOR_REFERENCE, USER_REFERENCE), document, null);

        // Saving a profile without touching the object is still allowed
        assertEquals("subject", getSubject(document));
    }
}
