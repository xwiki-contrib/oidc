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
package org.xwiki.contrib.oidc.internal;

import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.oidc.OAuth2Token;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Validate {@link UserOAuth2TokenStore}.
 *
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
class UserOAuth2TokenStoreTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @MockComponent
    private OIDCClientConfigurationStore configurationStore;

    @MockComponent
    private OAuth2TokenStoreCache cache;

    @InjectMockComponents
    private UserOAuth2TokenStore store;

    private OIDCClientConfiguration configuration1;

    private OIDCClientConfiguration configuration2;

    @BeforeEach
    void beforeEach() throws Exception
    {
        this.configuration1 = mockConfiguration("configuration1");
        this.configuration2 = mockConfiguration("configuration2");

        XWikiContext xcontext = this.oldcore.getXWikiContext();
        XWikiDocument userDocument = new XWikiDocument(USER_REFERENCE);
        addToken(userDocument, "configuration1", xcontext);
        addToken(userDocument, "configuration2", xcontext);
        this.oldcore.getSpyXWiki().saveDocument(userDocument, xcontext);
    }

    private OIDCClientConfiguration mockConfiguration(String name) throws Exception
    {
        OIDCClientConfiguration configuration = mock(OIDCClientConfiguration.class, name);
        when(configuration.getConfigurationName()).thenReturn(name);
        when(this.configurationStore.getOIDCClientConfiguration(name)).thenReturn(configuration);

        return configuration;
    }

    private void addToken(XWikiDocument document, String configurationName, XWikiContext xcontext) throws Exception
    {
        BaseObject object = document.newXObject(NimbusOAuth2Token.CLASS_REFERENCE, xcontext);
        object.setStringValue(NimbusOAuth2Token.FIELD_CLIENT_CONFIGURATION_NAME, configurationName);
        object.setStringValue(NimbusOAuth2Token.FIELD_TYPE, AccessTokenType.BEARER.getValue());
    }

    private OAuth2Token getToken(Set<OAuth2Token> tokens, OIDCClientConfiguration configuration)
    {
        return tokens.stream().filter(token -> token.getConfiguration() == configuration).findFirst().orElseThrow();
    }

    @Test
    void getTokens() throws Exception
    {
        Set<OAuth2Token> tokens = this.store.getTokens(USER_REFERENCE);

        assertEquals(2, tokens.size());
        getToken(tokens, this.configuration1);
        getToken(tokens, this.configuration2);
    }

    @Test
    void getTokensAfterDeletingAToken() throws Exception
    {
        this.store.deleteToken(getToken(this.store.getTokens(USER_REFERENCE), this.configuration1));

        Set<OAuth2Token> tokens = this.store.getTokens(USER_REFERENCE);

        assertEquals(1, tokens.size());
        getToken(tokens, this.configuration2);
    }
}
