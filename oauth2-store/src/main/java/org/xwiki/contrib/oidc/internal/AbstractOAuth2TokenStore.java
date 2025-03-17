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

import javax.inject.Inject;
import javax.inject.Provider;

import org.apache.tika.utils.StringUtils;
import org.slf4j.Logger;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Abstract implementation of {@link OAuth2TokenStore} which provides some utility methods to subclasses.
 *
 * @version $Id$
 * @since 2.15.0
 */
public abstract class AbstractOAuth2TokenStore implements OAuth2TokenStore
{
    @Inject
    protected Provider<XWikiContext> contextProvider;

    @Inject
    protected Logger logger;

    @Inject
    protected ContextualAuthorizationManager contextualAuthorizationManager;

    protected AccessToken getAccessToken(DocumentReference documentReference, OIDCClientConfiguration configuration)
        throws OAuth2Exception
    {
        OAuth2Token oAuth2Token = getOAuth2Token(documentReference, configuration);
        return (oAuth2Token == null) ? null : oAuth2Token.toAccessToken();
    }

    protected RefreshToken getRefreshToken(DocumentReference documentReference, OIDCClientConfiguration configuration)
        throws OAuth2Exception
    {
        OAuth2Token oAuth2Token = getOAuth2Token(documentReference, configuration);
        return (oAuth2Token == null) ? null : oAuth2Token.toRefreshToken();
    }

    protected OAuth2Token getOAuth2Token(DocumentReference documentReference,
        OIDCClientConfiguration configuration)
        throws OAuth2Exception
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        try {
            XWikiDocument document = xwiki.getDocument(documentReference, context);

            if (document.isNew() || document.getXObject(
                OAuth2Token.CLASS_REFERENCE, OAuth2Token.FIELD_CLIENT_CONFIGURATION_NAME,
                configuration.getConfigurationName(), false) == null) {
                return null;
            } else {
                return getOAuth2TokenFromDocument(document, configuration.getConfigurationName());
            }
        } catch (XWikiException e) {
            throw new OAuth2Exception(String.format("Failed to get token for [%s] in [%s]",
                configuration.getConfigurationName(), documentReference), e);
        }
    }

    protected void saveAccess(DocumentReference documentReference,
        OIDCClientConfiguration configuration, AccessToken accessToken, RefreshToken refreshToken)
        throws OAuth2Exception
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        try {
            XWikiDocument document = xwiki.getDocument(documentReference, context);

            if (contextualAuthorizationManager.hasAccess(Right.EDIT, documentReference)) {
                OAuth2Token token =
                    getOAuth2TokenFromDocument(document, configuration.getConfigurationName());
                token.fromAccessToken(accessToken);
                token.fromRefreshToken(refreshToken);

                // Don't create a new version of the document upon save
                document.setContentDirty(false);
                document.setMetaDataDirty(false);
                xwiki.saveDocument(document, String.format("Save OAuth2 token for [%s]",
                    configuration.getConfigurationName()), context);
            } else {
                throw new OAuth2Exception(
                    String.format("Current user [%s] has no edit rights on [%s] to save token for [%s]",
                        context.getUserReference(), documentReference, configuration.getConfigurationName()));
            }
        } catch (XWikiException e) {
            throw new OAuth2Exception(String.format("Failed to save token for [%s] in [%s]",
                configuration.getConfigurationName(), documentReference), e);
        }
    }

    private OAuth2Token getOAuth2TokenFromDocument(XWikiDocument document,
        String clientConfigurationName) throws XWikiException
    {
        BaseObject tokenObj = document.getXObject(OAuth2Token.CLASS_REFERENCE,
            OAuth2Token.FIELD_CLIENT_CONFIGURATION_NAME, clientConfigurationName, false);
        if (tokenObj == null) {
            tokenObj = document.getXObject(OAuth2Token.CLASS_REFERENCE, true, contextProvider.get());
        }

        OAuth2Token token = new OAuth2Token(tokenObj);

        if (StringUtils.isBlank(token.getClientConfigurationName())) {
            token.setClientConfigurationName(clientConfigurationName);
        }

        return token;
    }
}
