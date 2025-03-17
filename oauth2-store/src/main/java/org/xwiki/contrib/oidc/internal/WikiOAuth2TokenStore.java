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
import javax.inject.Named;

import org.xwiki.bridge.DocumentAccessBridge;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.OAuth2Exception;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;
import org.xwiki.model.reference.DocumentReference;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.xpn.xwiki.internal.mandatory.XWikiPreferencesDocumentInitializer;

import groovy.lang.Singleton;

/**
 * Store for OAuth2 access token storing at wiki level.
 *
 * @version $Id$
 * @since 2.15.0
 */
@Component
@Named("wiki")
@Singleton
public class WikiOAuth2TokenStore extends AbstractOAuth2TokenStore
{
    @Inject
    private DocumentAccessBridge documentAccessBridge;

    @Override
    public void setToken(OIDCClientConfiguration configuration, AccessToken accessToken, RefreshToken refreshToken)
        throws OAuth2Exception
    {
        saveAccess(getDocumentReference(), configuration, accessToken, refreshToken);
    }

    @Override
    public AccessToken getAccessToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        return getAccessToken(getDocumentReference(), configuration);
    }

    @Override
    public RefreshToken getRefreshToken(OIDCClientConfiguration configuration) throws OAuth2Exception
    {
        return getRefreshToken(getDocumentReference(), configuration);
    }

    private DocumentReference getDocumentReference()
    {
        return new DocumentReference(XWikiPreferencesDocumentInitializer.LOCAL_REFERENCE,
            documentAccessBridge.getCurrentDocumentReference().getWikiReference());
    }
}
