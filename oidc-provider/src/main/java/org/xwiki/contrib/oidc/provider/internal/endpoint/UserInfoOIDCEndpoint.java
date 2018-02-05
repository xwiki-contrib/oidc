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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.oidc.OIDCUserInfo;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCConsent;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCStore;
import org.xwiki.localization.LocaleUtils;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.WikiReference;

import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.objects.PropertyInterface;

/**
 * UserInfo endpoint for OpenID Connect.
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

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private EntityReferenceSerializer<String> serializer;

    @Inject
    private Logger logger;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        this.logger.debug("OIDC: Entering [userinfo] endpoint");

        // Parse the request
        UserInfoRequest request = UserInfoRequest.parse(httpRequest);

        // Get the token associated to the user
        AccessToken accessToken = request.getAccessToken();

        OIDCConsent consent = this.store.getConsent(accessToken);

        if (consent == null) {
            return new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);
        }

        ClaimsRequest claims = consent.getClaims();

        DocumentReference userReference = consent.getUserReference();

        UserInfo userInfo = new UserInfo(this.manager.getSubject(userReference));

        XWikiContext xcontext = this.xcontextProvider.get();

        BaseObject userObject = this.store.getUserObject(consent);
        XWikiDocument userDocument = userObject.getOwnerDocument();

        if (claims != null) {
            for (Entry claim : claims.getUserInfoClaims()) {
                try {
                    switch (claim.getClaimName()) {
                        // OIDC core

                        case OIDCUserInfo.CLAIM_ADDRESS:
                            String addressString = userObject.getLargeStringValue("address");
                            if (StringUtils.isNotEmpty(addressString)) {
                                Address address = new Address();
                                address.setFormatted(addressString);
                                userInfo.setAddress(address);
                            }
                            break;
                        case OIDCUserInfo.CLAIM_EMAIL:
                            String email = userObject.getStringValue("email");
                            if (StringUtils.isNotEmpty(email)) {
                                userInfo.setEmailAddress(email);
                            }
                            break;
                        case OIDCUserInfo.CLAIM_EMAIL_VERIFIED:
                            if (userInfo.getEmailAddress() != null) {
                                userInfo.setEmailVerified(true);
                            }
                            break;
                        case OIDCUserInfo.CLAIM_FAMILY_NAME:
                            userInfo.setFamilyName(getStringValue(userObject, "last_name"));
                            break;
                        case OIDCUserInfo.CLAIM_GIVEN_NAME:
                            userInfo.setGivenName(getStringValue(userObject, "first_name"));
                            break;
                        case OIDCUserInfo.CLAIM_PHONE_NUMBER:
                            userInfo.setPhoneNumber(getStringValue(userObject, "phone"));
                            break;
                        case OIDCUserInfo.CLAIM_PHONE_NUMBER_VERIFIED:
                            if (userInfo.getPhoneNumber() != null) {
                                userInfo.setPhoneNumberVerified(true);
                            }
                            break;
                        case OIDCUserInfo.CLAIM_PICTURE:
                            userInfo.setPicture(this.store.getUserAvatarURI(userDocument));
                            break;
                        case OIDCUserInfo.CLAIM_PROFILE:
                            userInfo.setProfile(this.store.getUserProfileURI(userDocument));
                            break;
                        case OIDCUserInfo.CLAIM_UPDATED_AT:
                            userInfo.setUpdatedTime(userDocument.getDate());
                            break;
                        case OIDCUserInfo.CLAIM_WEBSITE:
                            String blog = userObject.getStringValue("blog");
                            if (StringUtils.isNotEmpty(blog)) {
                                userInfo.setWebsite(new URI(blog));
                            }
                            break;
                        case OIDCUserInfo.CLAIM_NAME:
                            userInfo.setName(xcontext.getWiki().getPlainUserName(userReference, xcontext));
                            break;
                        case OIDCUserInfo.CLAIM_PREFERRED_NAME:
                            userInfo.setPreferredUsername(xcontext.getWiki().getPlainUserName(userReference, xcontext));
                            break;
                        case OIDCUserInfo.CLAIM_ZONEINFO:
                            String timezone = userObject.getStringValue("timezone");
                            if (StringUtils.isNotEmpty(timezone)) {
                                userInfo.setZoneinfo(timezone);
                            }
                            break;
                        case OIDCUserInfo.CLAIM_LOCALE:
                            String locale = userObject.getStringValue("default_language");
                            if (StringUtils.isNotEmpty(locale)) {
                                userInfo.setLocale(LocaleUtils.toLocale(locale).toLanguageTag());
                            }
                            break;
                        case OIDCUserInfo.CLAIM_MIDDLE_NAME:
                        case OIDCUserInfo.CLAIM_NICKNAME:
                        case OIDCUserInfo.CLAIM_GENDER:
                        case OIDCUserInfo.CLAIM_BIRTHDATE:
                            // TODO
                            break;

                        // XWiki core
                        // Note: most of the XWiki core fields are handled by #setCustomUserInfoClaim

                        case OIDCUserInfo.CLAIM_XWIKI_GROUPS:
                            userInfo.setClaim(OIDCUserInfo.CLAIM_XWIKI_GROUPS, getUserGroups(userDocument, xcontext));
                            break;

                        default:
                            setCustomUserInfoClaim(userInfo, claim, userObject, userDocument, xcontext);
                            break;
                    }
                } catch (Exception e) {
                    // Failed to set one of the claims
                    this.logger.warn("Failed to get claim [{}] for user [{}]: {}", claim.getClaimName(), userReference,
                        ExceptionUtils.getRootCauseMessage(e));
                }
            }
        } else {
            // Most probably OpenID Connect
            String email = userObject.getStringValue("email");
            if (StringUtils.isNotEmpty(email)) {
                userInfo.setEmailAddress(email);
                userInfo.setEmailVerified(true);
            }

            userInfo.setName(xcontext.getWiki().getPlainUserName(userReference, xcontext));
            userInfo.setPreferredUsername(xcontext.getWiki().getPlainUserName(userReference, xcontext));

            userInfo.setPicture(this.store.getUserAvatarURI(userDocument));

            userInfo.setProfile(this.store.getUserProfileURI(userDocument));
        }

        this.logger.debug("OIDC.userinfo: User infos: [{}]", userInfo.toJSONObject());

        return new UserInfoSuccessResponse(userInfo);
    }

    private String getStringValue(BaseObject obj, String key)
    {
        String value = obj.getStringValue(key);

        return StringUtils.isEmpty(value) ? null : value;
    }

    private Collection<String> getUserGroups(XWikiDocument userDocument, XWikiContext xcontext) throws XWikiException
    {
        List<String> names;

        WikiReference currentWikiReference = xcontext.getWikiReference();

        try {
            // Switch to user wiki
            xcontext.setWikiReference(userDocument.getDocumentReference().getWikiReference());

            // Get groups in user wiki
            Collection<DocumentReference> references = xcontext.getWiki().getGroupService(xcontext)
                .getAllGroupsReferencesForMember(userDocument.getDocumentReference(), -1, 0, xcontext);

            // Convert reference into Strings
            names = new ArrayList<>(references.size());
            for (DocumentReference reference : references) {
                // TODO: also search groups of group
                names.add(this.serializer.serialize(reference));
            }
        } finally {
            xcontext.setWikiReference(currentWikiReference);
        }

        return names;
    }

    private void setCustomUserInfoClaim(UserInfo userInfo, Entry claim, BaseObject userObject,
        XWikiDocument userDocument, XWikiContext xcontext)
    {
        if (claim.getClaimName().startsWith(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER)) {
            String userField = claim.getClaimName().substring(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER.length());

            // Try user object first
            PropertyInterface property = userObject.safeget(userField);

            if (property != null) {
                userInfo.setClaim(claim.getClaimName(), ((BaseProperty) property).getValue());
            } else {
                // Try the whole document if not in user object
                BaseObject obj = userDocument.getFirstObject(userField, xcontext);
                if (obj != null) {
                    property = obj.safeget(userField);
                    if (property != null) {
                        userInfo.setClaim(claim.getClaimName(), ((BaseProperty) property).getValue());
                    }
                }
            }
        }
    }
}
