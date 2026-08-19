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
import org.xwiki.contrib.oidc.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceSerializer;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWikiContext;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link OIDCConsentStore}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class OIDCConsentStoreTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    private static final DocumentReference OTHERUSER_REFERENCE = new DocumentReference("xwiki", "XWiki", "OtherUser");

    private static final LocalDocumentReference USERS_CLASS_REFERENCE =
        new LocalDocumentReference("XWiki", "XWikiUsers");

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @MockComponent
    private WikiDescriptorManager wikiDescriptorManager;

    @MockComponent
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    // Used when an xobject is serialized as part of an error message
    @MockComponent
    private XWikiDocumentFilterUtils filterUtils;

    @InjectMockComponents
    private OIDCConsentClassDocumentInitializer classInitializer;

    @InjectMockComponents
    private OIDCConsentStore store;

    private UserReference user;

    private UserReference otherUser;

    @BeforeEach
    void beforeEach() throws Exception
    {
        XWikiContext xcontext = this.oldcore.getXWikiContext();

        // Make sure the consent class exist since creating a consent requires it
        XWikiDocument classDocument = this.oldcore.getSpyXWiki()
            .getDocument(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, xcontext.getWikiReference()), xcontext);
        this.classInitializer.updateDocument(classDocument);
        this.oldcore.getSpyXWiki().saveDocument(classDocument, xcontext);

        this.user = mock(UserReference.class, "user");
        when(this.userReferenceSerializer.serialize(this.user)).thenReturn(USER_REFERENCE);
        this.otherUser = mock(UserReference.class, "otheruser");
        when(this.userReferenceSerializer.serialize(this.otherUser)).thenReturn(OTHERUSER_REFERENCE);

        // A user with two consents and a user xobject
        XWikiDocument userDocument = new XWikiDocument(USER_REFERENCE);
        userDocument.newXObject(USERS_CLASS_REFERENCE, xcontext);
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

    @Test
    void deleteConsent() throws Exception
    {
        this.store.deleteConsent(this.user, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]");

        assertNull(getConsentObject(0));
        // The other consent and the user xobject are untouched
        assertNotNull(getConsentObject(1));
        assertNotNull(getUserDocument().getXObject(USERS_CLASS_REFERENCE));
    }

    @Test
    void deleteConsentWithRelativeId() throws Exception
    {
        this.store.deleteConsent(this.user, "XWiki.User^XWiki.OIDC.ConsentClass[1]");

        assertNull(getConsentObject(1));
        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentOfAnotherUser() throws Exception
    {
        OIDCException exception = assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(this.otherUser, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]"));

        assertEquals("The consent [xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]] is not associated to the user"
            + " [xwiki:XWiki.OtherUser]", exception.getMessage());

        // Nothing was deleted
        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithObjectOfAnotherClass() throws Exception
    {
        OIDCException exception = assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(this.user, "xwiki:XWiki.User^XWiki.XWikiUsers[0]"));

        assertEquals("The object [xwiki:XWiki.User^XWiki.XWikiUsers[0]] is not a consent", exception.getMessage());

        // Nothing was deleted
        assertNotNull(getUserDocument().getXObject(USERS_CLASS_REFERENCE));
    }

    @Test
    void deleteConsentWithoutUser()
    {
        OIDCException exception = assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(null, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]"));

        assertEquals("A valid user reference is required to delete the consent"
            + " [xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]]", exception.getMessage());
    }

    @Test
    void deleteConsentWithUnknownUser()
    {
        UserReference unknownUser = mock(UserReference.class, "unknown");

        assertThrows(OIDCException.class,
            () -> this.store.deleteConsent(unknownUser, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]"));
    }

    @Test
    void deleteConsentWithUnknownDocument() throws Exception
    {
        when(this.userReferenceSerializer.serialize(this.user))
            .thenReturn(new DocumentReference("xwiki", "XWiki", "NoSuchUser"));

        // Nothing to delete, but no error either
        this.store.deleteConsent(this.user, "xwiki:XWiki.NoSuchUser^XWiki.OIDC.ConsentClass[0]");

        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithUnknownConsent() throws Exception
    {
        // Nothing to delete, but no error either
        this.store.deleteConsent(this.user, "xwiki:XWiki.User^XWiki.OIDC.ConsentClass[42]");

        assertNotNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithoutUserCheck() throws Exception
    {
        this.store.deleteConsent("xwiki:XWiki.User^XWiki.OIDC.ConsentClass[0]");

        assertNull(getConsentObject(0));
    }

    @Test
    void deleteConsentWithoutUserCheckAndObjectOfAnotherClass() throws Exception
    {
        // Even when the user is not checked, only a consent can be deleted
        assertThrows(OIDCException.class, () -> this.store.deleteConsent("xwiki:XWiki.User^XWiki.XWikiUsers[0]"));

        assertNotNull(getUserDocument().getXObject(USERS_CLASS_REFERENCE));
    }
}
