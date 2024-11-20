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
import org.xwiki.contrib.oidc.OAuth2AccessTokenStore;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Abstract implementation of {@link OAuth2AccessTokenStore} which provides some utility methods to subclasses.
 *
 * @version $Id$
 * @since 2.14.0
 */
public abstract class AbstractOAuth2AccessTokenStore implements OAuth2AccessTokenStore
{
    @Inject
    protected Provider<XWikiContext> contextProvider;

    @Inject
    protected Logger logger;

    @Inject
    protected ContextualAuthorizationManager contextualAuthorizationManager;

    protected OAuth2AccessToken getAccessToken(DocumentReference documentReference,
        OIDCClientConfiguration configuration)
        throws OAuth2Exception
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        try {
            XWikiDocument document = xwiki.getDocument(documentReference, context);

            return getAccessTokenFromDocument(document, configuration.getConfigurationName());
        } catch (XWikiException e) {
            throw new OAuth2Exception(String.format("Failed to get access token for [%s] in [%s]",
                configuration.getConfigurationName(), documentReference), e);
        }
    }

    protected void saveAccessToken(DocumentReference documentReference,
        OIDCClientConfiguration configuration, AccessToken accessToken) throws OAuth2Exception
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        try {
            XWikiDocument document = xwiki.getDocument(documentReference, context);

            if (contextualAuthorizationManager.hasAccess(Right.EDIT, documentReference)) {
                OAuth2AccessToken token = getAccessTokenFromDocument(document, configuration.getConfigurationName());
                token.fromAccessToken(accessToken);

                xwiki.saveDocument(document, String.format("Save OAuth2 access token for [%s]",
                    configuration.getConfigurationName()), context);
            } else {
                throw new OAuth2Exception(
                    String.format("Current user [%s] has no edit rights on [%s] to save access token for [%s]",
                        context.getUserReference(), documentReference, configuration.getConfigurationName()));
            }
        } catch (XWikiException e) {
            throw new OAuth2Exception(String.format("Failed to save access token for [%s] in [%s]",
                configuration.getConfigurationName(), documentReference), e);
        }
    }

    private OAuth2AccessToken getAccessTokenFromDocument(XWikiDocument document, String clientConfigurationName)
        throws XWikiException
    {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            document.getXObject(OAuth2AccessToken.CLASS_REFERENCE,
                OAuth2AccessToken.FIELD_CLIENT_CONFIGURATION_NAME, clientConfigurationName, true));

        if (StringUtils.isBlank(accessToken.getClientConfigurationName())) {
            accessToken.setClientConfigurationName(clientConfigurationName);
        }

        return accessToken;
    }
}
