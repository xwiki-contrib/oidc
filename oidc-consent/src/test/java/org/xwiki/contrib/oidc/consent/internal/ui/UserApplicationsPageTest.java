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
import java.util.Map;

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
import org.xwiki.csrf.script.CSRFTokenScriptService;
import org.xwiki.icon.IconManagerScriptService;
import org.xwiki.localization.macro.internal.TranslationMacro;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.properties.converter.Converter;
import org.xwiki.rendering.configuration.ExtendedRenderingConfiguration;
import org.xwiki.rendering.internal.code.layout.PlainLayoutHandler;
import org.xwiki.rendering.internal.macro.code.CodeMacro;
import org.xwiki.rendering.internal.macro.code.source.CodeMacroSourceReferenceConverter;
import org.xwiki.rendering.internal.macro.code.source.DefaultCodeMacroSourceFactory;
import org.xwiki.rendering.internal.macro.code.source.StringCodeMacroSourceFactory;
import org.xwiki.rendering.internal.macro.message.ErrorMessageMacro;
import org.xwiki.rendering.internal.macro.message.InfoMessageMacro;
import org.xwiki.rendering.internal.macro.message.SuccessMessageMacro;
import org.xwiki.rendering.internal.macro.message.WarningMessageMacro;
import org.xwiki.rendering.internal.syntax.SyntaxConverter;
import org.xwiki.rendering.macro.MacroCategoryManager;
import org.xwiki.rendering.script.RenderingScriptService;
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
import com.xpn.xwiki.user.api.XWikiAuthService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validate the {@code oidc/consent/userapplications.vm} template: consent creation and the messages displayed for each
 * consent.
 *
 * @version $Id$
 */
@HTML50ComponentList
@XWikiSyntax21ComponentList
@ComponentList({OIDCScriptService.class, OIDCConsentScriptService.class, SyntaxConverter.class,
    RenderingScriptService.class, TranslationMacro.class, SuccessMessageMacro.class, WarningMessageMacro.class,
    ErrorMessageMacro.class, InfoMessageMacro.class, CodeMacro.class, DefaultCodeMacroSourceFactory.class,
    StringCodeMacroSourceFactory.class, CodeMacroSourceReferenceConverter.class, PlainLayoutHandler.class})
class UserApplicationsPageTest extends PageTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    private static final String CLEAR_REJECTED = "oidc.template.userapplications.clearToken.rejected";

    private static final String CLEAR_ALLOWED = "oidc.template.userapplications.clearToken.allowed";

    private static final String DEPRECATED_VERSION = "oidc.template.userapplications.deprecatedVersion";

    private static final String FORM_TOKEN = "formtoken";

    @MockComponent
    private OIDCConsentStore store;

    @MockComponent
    private OIDCConsentConfiguration configuration;

    // Needed by the rendering script service
    @MockComponent
    private ExtendedRenderingConfiguration renderingConfiguration;

    // Needed by the rendering script service
    @MockComponent
    private MacroCategoryManager macroCategoryManager;

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

    private void requestConsentCreation(String applicationName) throws Exception
    {
        CSRFTokenScriptService csrfService = mock(CSRFTokenScriptService.class);
        when(csrfService.isTokenValid(FORM_TOKEN)).thenReturn(true);
        this.componentManager.registerComponent(ScriptService.class, "csrf", csrfService);

        this.request.put("form_token", FORM_TOKEN);
        this.request.put("oidc_consent_create", "");
        this.request.put("application_name", applicationName);
    }

    @Test
    void createConsentDisplaysApplicationNameAsPlainText() throws Exception
    {
        // Wiki syntax in the application name must not be interpreted when displaying the created consent
        String applicationName = "**bold** [[label>>https://www.xwiki.org]] {{info}}macro{{/info}} \"quote\" ~tilde";
        requestConsentCreation(applicationName);

        BaseObjectOIDCConsent consent = mockConsent(applicationName, 2, false);
        when(consent.getAccessTokenValue()).thenReturn("tokenvalue");
        when(this.store.createAndSaveConsent(any(), any(), any())).thenReturn(consent);
        when(this.store.getConsents(any())).thenReturn(List.of(consent));

        Document document = Jsoup.parse(this.templateManager.render("oidc/consent/userapplications.vm"));

        Elements successBoxes = document.select("div.successmessage");
        assertEquals(1, successBoxes.size(), document.outerHtml());
        Element successBox = successBoxes.first();
        // The box title is the only text directly in the box
        assertEquals(applicationName, successBox.ownText(), successBox.outerHtml());
        assertEquals(0, successBox.select("strong, a").size(), successBox.outerHtml());
        assertEquals(0, document.select("div.infomessage").size(), document.outerHtml());
        assertTrue(successBox.text().contains("Bearer tokenvalue"), successBox.outerHtml());
    }

    @Test
    void createConsentWhenDisabled() throws Exception
    {
        // A configured authenticator which does not support tokens
        this.componentManager.registerComponent(ScriptService.class, "security",
            new TestSecurityScriptService(mock(XWikiAuthService.class)));
        when(this.configuration.isCreateConsentEnabled()).thenReturn(false);

        requestConsentCreation("application");

        Document document = Jsoup.parse(this.templateManager.render("oidc/consent/userapplications.vm"));

        verify(this.store, never()).createAndSaveConsent(any(), any(), any());
        assertEquals(0, document.select("div.successmessage").size(), document.outerHtml());
        Elements errors = document.select("div.errormessage");
        assertEquals(1, errors.size(), document.outerHtml());
        assertEquals("notallowed", errors.first().text());
        assertEquals(0, document.select("form #input_application_name").size(), document.outerHtml());
    }

    /**
     * Expose the configured authenticator the way {@code $services.security.authService.authService} does.
     */
    public static class TestSecurityScriptService implements ScriptService
    {
        private final Map<String, XWikiAuthService> authService;

        TestSecurityScriptService(XWikiAuthService authService)
        {
            this.authService = Map.of("authService", authService);
        }

        /**
         * @return the authenticator script service
         */
        public Map<String, XWikiAuthService> getAuthService()
        {
            return this.authService;
        }
    }
}
