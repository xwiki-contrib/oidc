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
package org.xwiki.contrib.oidc.provider.internal;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.contrib.oidc.provider.internal.store.XWikiBearerAccessToken;
import org.xwiki.model.reference.EntityReferenceSerializer;

import com.nimbusds.oauth2.sdk.ParseException;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;

/**
 * Check if the request contains a OIDC access token.
 * 
 * @version $Id$
 * @since 1.15
 */
@Component(roles = OIDCProviderAuthenticator.class)
@Singleton
public class OIDCProviderAuthenticator
{
    @Inject
    private OIDCStore oidcStore;

    @Inject
    @Named("compact")
    private EntityReferenceSerializer<String> serializer;

    /**
     * @param authorizationString the authorization String (generally coming from a HTTP request)
     * @return the corresponding user or null if none could be found
     * @throws ParseException when failing to validate the token
     * @throws XWikiException when failing to validate the token
     */
    public XWikiUser checkAuth(String authorizationString) throws ParseException, XWikiException
    {
        if (StringUtils.isNotEmpty(authorizationString)) {
            XWikiBearerAccessToken xwikiAccessToken = XWikiBearerAccessToken.parse(authorizationString);

            if (xwikiAccessToken != null) {
                OIDCConsent consent = this.oidcStore.getConsent(xwikiAccessToken);

                if (consent != null) {
                    return new XWikiUser(this.serializer.serialize(consent.getUserReference()));
                }
            }
        }

        return null;
    }
}
