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
package org.xwiki.contrib.oidc.provider.internal.endpoint;

import java.net.URI;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * UserInfo endpoint for OpenId Connect.
 * 
 * @version $Id$
 */
@Component
@Named(UserInfoOIDCEndpoint.HINT)
@Singleton
public class UserInfoOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "userinfo";

    @Inject
    private OIDCStore store;

    @Inject
    private OIDCManager manager;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        UserInfoRequest request = UserInfoRequest.parse(httpRequest);

        // Get the token associated to the user
        AccessToken accessToken = request.getAccessToken();

        OIDCConsent consent = this.store.getConsent(accessToken);

        if (consent == null) {
            return new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);
        }

        // TODO: get the claims from the consent

        BaseObject userObject = this.store.getUserObject(consent);
        XWikiDocument userDocument = userObject.getOwnerDocument();

        UserInfo userInfo = new UserInfo(this.manager.getSubject(consent.getUserReference()));

        // Update time
        userInfo.setUpdatedTime(userDocument.getDate());

        // Address
        Address address = new Address();
        address.setFormatted(userObject.getLargeStringValue("address"));
        userInfo.setAddress(address);

        // Email
        String email = userObject.getStringValue("email");
        if (StringUtils.isNotEmpty(email)) {
            try {
                userInfo.setEmail(new InternetAddress(email));
            } catch (AddressException e) {
                // TODO: log
            }
        }

        // Last name
        userInfo.setFamilyName(userObject.getStringValue("last_name"));

        // First name
        userInfo.setGivenName(userObject.getStringValue("first_name"));

        // Phone
        userInfo.setPhoneNumber(userObject.getStringValue("phone"));

        // Avatar
        URI avatarURI = this.store.getUserAvatarURI(userDocument);
        if (avatarURI != null) {
            userInfo.setPicture(avatarURI);
        }

        // Profile external URL
        userInfo.setProfile(this.store.getUserProfileURI(userDocument));

        return new UserInfoSuccessResponse(userInfo);
    }
}
