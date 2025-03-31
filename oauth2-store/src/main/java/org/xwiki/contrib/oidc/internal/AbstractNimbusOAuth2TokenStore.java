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

import org.xwiki.contrib.oidc.OAuth2Token;
import org.xwiki.contrib.oidc.OAuth2TokenStore;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

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
public abstract class AbstractNimbusOAuth2TokenStore implements OAuth2TokenStore
{
    @Inject
    protected Provider<XWikiContext> contextProvider;

    @Inject
    protected ContextualAuthorizationManager contextualAuthorizationManager;

    /**
     * Provide the document to be used for storing oauth2 tokens for the given configuration.
     *
     * @param configuration the configuration to use
     * @return a reference to the document that should be used to store tokens
     * @throws OAuth2Exception if an error happens
     */
    protected abstract DocumentReference getConfiguredDocumentReference(OIDCClientConfiguration configuration)
        throws OAuth2Exception;

    @Override
    public void saveToken(OAuth2Token token) throws OAuth2Exception
    {
        saveToken(getConfiguredDocumentReference(token.getConfiguration()), token);
    }

    protected void saveToken(DocumentReference documentReference, OAuth2Token token)
        throws OAuth2Exception
    {
        if (token instanceof NimbusOAuth2Token) {
            XWikiContext context = contextProvider.get();
            XWiki xwiki = context.getWiki();

            try {
                XWikiDocument document = xwiki.getDocument(documentReference, context);

                if (contextualAuthorizationManager.hasAccess(Right.EDIT, documentReference)) {
                    BaseObject object = document.getXObject(NimbusOAuth2Token.CLASS_REFERENCE,
                        NimbusOAuth2Token.FIELD_CLIENT_CONFIGURATION_NAME,
                        token.getConfiguration().getConfigurationName(), true);
                    ((NimbusOAuth2Token) token).applyTo(object);

                    // Don't create a new version of the document upon save
                    document.setContentDirty(false);
                    document.setMetaDataDirty(false);
                    xwiki.saveDocument(document, String.format("Save OAuth2 token for [%s]",
                        token.getConfiguration().getConfigurationName()), context);
                } else {
                    throw new OAuth2Exception(
                        String.format("Current user [%s] has no edit rights on [%s] to save token for [%s]",
                            context.getUserReference(), documentReference,
                            token.getConfiguration().getConfigurationName()));
                }
            } catch (XWikiException e) {
                throw new OAuth2Exception(String.format("Failed to save token for [%s] in [%s]",
                    token.getConfiguration().getConfigurationName(), documentReference), e);
            }
        } else {
            throw new OAuth2Exception(String.format("Unsupported token type [%s]", token.getClass().getName()));
        }
    }

    @Override
    public OAuth2Token getToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        return getToken(getConfiguredDocumentReference(configuration), configuration);
    }

    protected NimbusOAuth2Token getToken(DocumentReference documentReference,
        OIDCClientConfiguration configuration)
        throws OAuth2Exception
    {
        XWikiContext context = contextProvider.get();
        XWiki xwiki = context.getWiki();

        try {
            XWikiDocument document = xwiki.getDocument(documentReference, context);
            BaseObject tokenObj = document.getXObject(
                NimbusOAuth2Token.CLASS_REFERENCE, NimbusOAuth2Token.FIELD_CLIENT_CONFIGURATION_NAME,
                configuration.getConfigurationName(), false);

            if (document.isNew() || tokenObj == null) {
                return null;
            } else {
                return new NimbusOAuth2Token(configuration, tokenObj);
            }
        } catch (XWikiException e) {
            throw new OAuth2Exception(String.format("Failed to get token for [%s] in [%s]",
                configuration.getConfigurationName(), documentReference), e);
        }
    }

    @Override
    public void deleteToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        deleteToken(getToken(getConfiguredDocumentReference(configuration), configuration));
    }

    @Override
    public void deleteToken(OAuth2Token token) throws OAuth2Exception
    {
        if (token instanceof NimbusOAuth2Token) {
            XWikiContext context = contextProvider.get();
            XWiki xwiki = context.getWiki();

            try {
                XWikiDocument document =
                    xwiki.getDocument(token.getReference().getDocumentReference(), context);
                document.removeXObject(document.getXObject(token.getReference()));

                // Don't create a new version of the document upon save
                document.setContentDirty(false);
                document.setMetaDataDirty(false);
                xwiki.saveDocument(document, "Remove OAuth2 token", context);
            } catch (XWikiException e) {
                throw new OAuth2Exception(String.format("Failed to remove token for [%s]", token.getReference()), e);
            }
        } else {
            throw new OAuth2Exception("This store only supports deleting NimbusOAuth2Token");
        }
    }

    @Override
    public ObjectReference getConfiguredObjectReference(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        NimbusOAuth2Token existingToken = getToken(getConfiguredDocumentReference(configuration), configuration);

        if (existingToken != null) {
            return existingToken.getReference();
        } else {
            XWikiContext context = contextProvider.get();
            XWiki xwiki = context.getWiki();

            try {
                XWikiDocument document = xwiki.getDocument(getConfiguredDocumentReference(configuration), context);
                return document.newXObject(NimbusOAuth2Token.CLASS_REFERENCE, context).getReference();

            } catch (XWikiException e) {
                throw new OAuth2Exception(String.format(
                    "Failed to get configured object reference for configuration [%s]",
                    configuration.getConfigurationName()), e);
            }
        }
    }
}
