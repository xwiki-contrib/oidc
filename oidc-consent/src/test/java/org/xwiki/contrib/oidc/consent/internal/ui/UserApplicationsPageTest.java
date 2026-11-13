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
package org.xwiki.contrib.oidc.consent.internal.ui;

import java.util.List;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.consent.internal.OIDCConsentConfiguration;
import org.xwiki.contrib.oidc.consent.internal.store.BaseObjectOIDCConsent;
import org.xwiki.contrib.oidc.consent.internal.store.OIDCConsentStore;
import org.xwiki.contrib.oidc.consent.script.OIDCConsentScriptService;
import org.xwiki.contrib.oidc.script.OIDCScriptService;
import org.xwiki.icon.IconManagerScriptService;
import org.xwiki.localization.macro.internal.TranslationMacro;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.properties.converter.Converter;
import org.xwiki.rendering.syntax.Syntax;
import org.xwiki.script.service.ScriptService;
import org.xwiki.template.TemplateManager;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.test.page.HTML50ComponentList;
import org.xwiki.test.page.PageTest;
import org.xwiki.test.page.XWikiSyntax21ComponentList;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.doc.XWikiDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate the messages displayed for each consent by the {@code oidc/consent/userapplications.vm} template.
 *
 * @version $Id$
 */
@HTML50ComponentList
@XWikiSyntax21ComponentList
@ComponentList({OIDCScriptService.class, OIDCConsentScriptService.class, TranslationMacro.class})
class UserApplicationsPageTest extends PageTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    private static final String CLEAR_REJECTED = "oidc.template.userapplications.clearToken.rejected";

    private static final String CLEAR_ALLOWED = "oidc.template.userapplications.clearToken.allowed";

    private static final String DEPRECATED_VERSION = "oidc.template.userapplications.deprecatedVersion";

    @MockComponent
    private OIDCConsentStore store;

    @MockComponent
    private OIDCConsentConfiguration configuration;

    // Convert the reference of the current document passed by the template to the script service
    @MockComponent
    private Converter<UserReference> userReferenceConverter;

    private TemplateManager templateManager;

    @BeforeEach
    void beforeEach() throws Exception
    {
        this.templateManager = this.componentManager.getInstance(TemplateManager.class);

        IconManagerScriptService iconService = mock(IconManagerScriptService.class);
        when(iconService.renderHTML(anyString()))
            .then(invocation -> "<span class=\"icon-" + invocation.getArgument(0) + "\"></span>");
        this.componentManager.registerComponent(ScriptService.class, "icon", iconService);

        UserReference userReference = mock(UserReference.class);
        when(this.userReferenceConverter.convert(any(), any())).thenReturn(userReference);

        // The profile of the current user
        XWikiDocument userDocument = new XWikiDocument(USER_REFERENCE);
        userDocument.newXObject(new LocalDocumentReference("XWiki", "XWikiUsers"), this.context);
        this.context.setDoc(userDocument);
        this.context.setUserReference(USER_REFERENCE);

        setOutputSyntax(Syntax.HTML_5_0);
    }

    private BaseObjectOIDCConsent mockConsent(String clientID, int version, boolean storedInClear)
    {
        BaseObjectOIDCConsent consent = mock(BaseObjectOIDCConsent.class);
        when(consent.getId()).thenReturn(clientID);
        when(consent.getClientID()).thenReturn(clientID);
        when(consent.getVersion()).thenReturn(version);
        when(consent.isAccessTokenStoredInClear()).thenReturn(storedInClear);

        return consent;
    }

    /**
     * @return the messages displayed in the box of the consent with the passed client ID
     */
    private Elements getConsentMessages(Document document, String clientID)
    {
        for (Element box : document.select("div.box")) {
            if (box.select("strong").text().equals(clientID)) {
                return box.select("div.small");
            }
        }

        throw new AssertionError("No consent box found for client [" + clientID + "]");
    }

    private void assertMessage(Elements messages, String expectedClass, String expectedIcon, String expectedKey)
    {
        assertEquals(1, messages.size());
        Element message = messages.first();
        assertTrue(message.hasClass(expectedClass), message.outerHtml());
        assertEquals(1, message.select("span.icon-" + expectedIcon).size(), message.outerHtml());
        assertEquals(expectedKey, message.text());
    }

    private Document render() throws Exception
    {
        List<BaseObjectOIDCConsent> consents = List.of(mockConsent("clear-v2", 2, true),
            mockConsent("clear-v1", 1, true), mockConsent("v1", 1, false), mockConsent("v2", 2, false));
        when(this.store.getConsents(any())).thenReturn(consents);

        return Jsoup.parse(this.templateManager.render("oidc/consent/userapplications.vm"));
    }

    @Test
    void consentMessagesWhenClearAccessTokenRejected() throws Exception
    {
        Document document = render();

        // An access token stored in clear is invalid, whatever the version of the consent
        assertMessage(getConsentMessages(document, "clear-v2"), "text-danger", "error", CLEAR_REJECTED);
        assertMessage(getConsentMessages(document, "clear-v1"), "text-danger", "error", CLEAR_REJECTED);
        // A hashed version 1 token is still valid, but stored in a less secure way
        assertMessage(getConsentMessages(document, "v1"), "text-warning", "warning", DEPRECATED_VERSION);
        assertEquals(0, getConsentMessages(document, "v2").size());
    }

    @Test
    void consentMessagesWhenClearAccessTokenAllowed() throws Exception
    {
        when(this.configuration.isClearAccessTokenAllowed()).thenReturn(true);

        Document document = render();

        assertMessage(getConsentMessages(document, "clear-v2"), "text-warning", "warning", CLEAR_ALLOWED);
        assertMessage(getConsentMessages(document, "clear-v1"), "text-warning", "warning", CLEAR_ALLOWED);
        assertMessage(getConsentMessages(document, "v1"), "text-warning", "warning", DEPRECATED_VERSION);
        assertEquals(0, getConsentMessages(document, "v2").size());
    }
}
