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
package org.xwiki.contrib.oidc.auth.internal;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.context.concurrent.ExecutionContextRunnable;
import org.xwiki.contrib.oidc.OIDCUserInfo;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserStore;
import org.xwiki.contrib.oidc.event.OIDCUserEventData;
import org.xwiki.contrib.oidc.event.OIDCUserUpdated;
import org.xwiki.contrib.oidc.event.OIDCUserUpdating;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.QueryException;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.user.api.XWikiRightService;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Various tools to manipulate users.
 * 
 * @version $Id$
 * @since 1.2
 */
@Component(roles = OIDCUserManager.class)
@Singleton
public class OIDCUserManager
{
    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCUserStore store;

    @Inject
    private ObservationManager observation;

    @Inject
    private ComponentManager componentManager;

    @Inject
    private Logger logger;

    private Executor executor = Executors.newFixedThreadPool(1);

    public void updateUserInfoAsync() throws MalformedURLException, URISyntaxException
    {
        final URI userInfoEndpoint = this.configuration.getUserInfoOIDCEndpoint();
        final IDTokenClaimsSet idToken = this.configuration.getIdToken();
        final BearerAccessToken accessToken = this.configuration.getAccessToken();

        this.executor.execute(new ExecutionContextRunnable(new Runnable()
        {
            @Override
            public void run()
            {
                try {
                    updateUserInfo(userInfoEndpoint, idToken, accessToken);
                } catch (Exception e) {
                    logger.error("Failed to update user informations", e);
                }
            }
        }, this.componentManager));
    }

    public void checkUpdateUserInfo()
    {
        Date date = this.configuration.removeUserInfoExpirationDate();
        if (date != null) {
            if (date.before(new Date())) {
                try {
                    updateUserInfoAsync();
                } catch (Exception e) {
                    this.logger.error("Failed to update user informations", e);
                }

                // Restart user information expiration counter
                this.configuration.resetUserInfoExpirationDate();
            } else {
                // Put back the date
                this.configuration.setUserInfoExpirationDate(date);
            }
        }
    }

    public Principal updateUserInfo(BearerAccessToken accessToken)
        throws URISyntaxException, IOException, ParseException, OIDCException, XWikiException, QueryException
    {
        Principal principal =
            updateUserInfo(this.configuration.getUserInfoOIDCEndpoint(), this.configuration.getIdToken(), accessToken);

        // Restart user information expiration counter
        this.configuration.resetUserInfoExpirationDate();

        return principal;
    }

    public Principal updateUserInfo(URI userInfoEndpoint, IDTokenClaimsSet idToken, BearerAccessToken accessToken)
        throws IOException, ParseException, OIDCException, XWikiException, QueryException
    {
        // Get OIDC user info
        UserInfoRequest userinfoRequest = new UserInfoRequest(userInfoEndpoint, accessToken);
        HTTPRequest userinfoHTTP = userinfoRequest.toHTTPRequest();
        userinfoHTTP.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
            + this.getClass().getPackage().getImplementationVersion());
        HTTPResponse httpResponse = userinfoHTTP.send();
        UserInfoResponse userinfoResponse = UserInfoResponse.parse(httpResponse);

        if (!userinfoResponse.indicatesSuccess()) {
            UserInfoErrorResponse error = (UserInfoErrorResponse) userinfoResponse;
            throw new OIDCException("Failed to get user info", error.getErrorObject());
        }

        UserInfoSuccessResponse userinfoSuccessResponse = (UserInfoSuccessResponse) userinfoResponse;
        UserInfo userInfo = userinfoSuccessResponse.getUserInfo();

        // Update/Create XWiki user
        return updateUser(idToken, userInfo);
    }

    private Principal updateUser(IDTokenClaimsSet idToken, UserInfo userInfo) throws XWikiException, QueryException
    {
        XWikiDocument userDocument =
            this.store.searchDocument(idToken.getIssuer().getValue(), userInfo.getSubject().toString());

        XWikiDocument modifiableDocument;
        boolean newUser;
        if (userDocument == null) {
            userDocument = getNewUserDocument(idToken, userInfo);

            newUser = true;
            modifiableDocument = userDocument;
        } else {
            // Don't change the document author to not change document execution right

            newUser = false;
            modifiableDocument = userDocument.clone();
        }

        XWikiContext xcontext = this.xcontextProvider.get();

        // Set user fields
        BaseObject userObject = modifiableDocument
            .getXObject(xcontext.getWiki().getUserClass(xcontext).getDocumentReference(), true, xcontext);

        // Address
        Address address = userInfo.getAddress();
        if (address != null) {
            userObject.set("address", address.getFormatted(), xcontext);
        }

        // Email
        if (userInfo.getEmail() != null) {
            userObject.set("email", userInfo.getEmail().toUnicodeString(), xcontext);
        }

        // Last name
        if (userInfo.getFamilyName() != null) {
            userObject.set("last_name", userInfo.getFamilyName(), xcontext);
        }

        // First name
        if (userInfo.getGivenName() != null) {
            userObject.set("first_name", userInfo.getGivenName(), xcontext);
        }

        // Phone
        if (userInfo.getPhoneNumber() != null) {
            userObject.set("phone", userInfo.getPhoneNumber(), xcontext);
        }

        // Default locale
        if (userInfo.getLocale() != null) {
            userObject.set("default_language", Locale.forLanguageTag(userInfo.getLocale()).toString(), xcontext);
        }

        // Time Zone
        if (userInfo.getZoneinfo() != null) {
            userObject.set("timezone", userInfo.getZoneinfo(), xcontext);
        }

        // Website
        if (userInfo.getWebsite() != null) {
            userObject.set("blog", userInfo.getWebsite().toString(), xcontext);
        }

        // Avatar
        if (userInfo.getPicture() != null) {
            try {
                String filename = FilenameUtils.getName(userInfo.getPicture().toString());
                URLConnection connection = userInfo.getPicture().toURL().openConnection();
                connection.setRequestProperty("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
                    + this.getClass().getPackage().getImplementationVersion());
                try (InputStream content = connection.getInputStream()) {
                    modifiableDocument.addAttachment(filename, content, xcontext);
                }
                userObject.set("avatar", filename, xcontext);
            } catch (IOException e) {
                this.logger.warn("Failed to get user avatar from URL [{}]: {}", userInfo.getPicture(),
                    ExceptionUtils.getRootCauseMessage(e));
            }
        }

        // XWiki claims
        updateXWikiClaims(modifiableDocument, userObject.getXClass(xcontext), userObject, userInfo, xcontext);

        // Set OIDC fields
        this.store.updateOIDCUser(modifiableDocument, idToken.getIssuer().getValue(), userInfo.getSubject().getValue());

        // Prevent data to send with the event
        OIDCUserEventData eventData =
            new OIDCUserEventData(new NimbusOIDCIdToken(idToken), new NimbusOIDCUserInfo(userInfo));

        // Notify
        this.observation.notify(new OIDCUserUpdating(modifiableDocument.getDocumentReference()), modifiableDocument,
            eventData);

        // Apply the modifications
        if (newUser || userDocument.apply(modifiableDocument)) {
            String comment;
            if (newUser) {
                comment = "Create user from OpenID Connect";
            } else {
                comment = "Update user from OpenID Connect";
            }

            xcontext.getWiki().saveDocument(userDocument, comment, xcontext);

            // Now let's add new the user to XWiki.XWikiAllGroup
            if (newUser) {
                xcontext.getWiki().setUserDefaultGroup(userDocument.getFullName(), xcontext);
            }

            // Notify
            this.observation.notify(new OIDCUserUpdated(userDocument.getDocumentReference()), userDocument, eventData);
        }

        return new SimplePrincipal(userDocument.getPrefixedFullName());
    }

    private void updateXWikiClaims(XWikiDocument userDocument, BaseClass userClass, BaseObject userObject,
        UserInfo userInfo, XWikiContext xcontext)
    {
        for (Map.Entry<String, Object> entry : userInfo.toJSONObject().entrySet()) {
            if (entry.getKey().startsWith(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER)) {
                String xwikiKey = entry.getKey().substring(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER.length());

                // Try in the user object
                if (userClass.getField(xwikiKey) != null) {
                    setValue(userObject, xwikiKey, entry.getValue(), xcontext);

                    continue;
                }

                // Try in the whole user document
                BaseObject xobject = userDocument.getFirstObject(xwikiKey);
                if (xobject != null) {
                    setValue(xobject, xwikiKey, entry.getValue(), xcontext);

                    continue;
                }
            }
        }
    }

    private void setValue(BaseObject xobject, String key, Object value, XWikiContext xcontext)
    {
        Object cleanValue;

        if (value instanceof List) {
            cleanValue = value;
        } else {
            // Go through String to be safe
            // TODO: find a more effective converter (the best would be to userObject#set to be stronger)
            cleanValue = Objects.toString(value);
        }

        xobject.set(key, cleanValue, xcontext);
    }

    private XWikiDocument getNewUserDocument(IDTokenClaimsSet idToken, UserInfo userInfo) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        // TODO: add support for subwikis
        SpaceReference spaceReference = new SpaceReference(xcontext.getMainXWiki(), "XWiki");

        // Generate default document name
        String documentName = formatUserName(idToken, userInfo);

        // Find not already existing document
        DocumentReference reference = new DocumentReference(documentName, spaceReference);
        XWikiDocument document = xcontext.getWiki().getDocument(reference, xcontext);
        for (int index = 0; !document.isNew(); ++index) {
            reference = new DocumentReference(documentName + '-' + index, spaceReference);

            document = xcontext.getWiki().getDocument(reference, xcontext);
        }

        // Initialize document
        document.setCreator(XWikiRightService.SUPERADMIN_USER);
        document.setAuthorReference(document.getCreatorReference());
        document.setContentAuthorReference(document.getCreatorReference());
        xcontext.getWiki().protectUserPage(document.getFullName(), "edit", document, xcontext);

        return document;
    }

    private String clean(String str)
    {
        return StringUtils.removePattern(str, "[\\.\\:\\s,@\\^]");
    }

    private void putVariable(Map<String, String> map, String key, String value)
    {
        map.put(key, value);
        map.put(key + ".clean", clean(value));
    }

    private String formatUserName(IDTokenClaimsSet idToken, UserInfo userInfo)
    {
        Map<String, String> map = new HashMap<>();

        // User informations
        putVariable(map, "oidc.user.subject", userInfo.getSubject().getValue());
        putVariable(map, "oidc.user.mail", userInfo.getEmail() == null ? "" : userInfo.getEmail().getAddress());
        putVariable(map, "oidc.user.familyName", userInfo.getFamilyName());
        putVariable(map, "oidc.user.givenName", userInfo.getGivenName());

        // Provider (only XWiki OIDC providers)
        URL providerURL = this.configuration.getXWikiProvider();
        if (providerURL != null) {
            putVariable(map, "oidc.provider", providerURL.toString());
            putVariable(map, "oidc.provider.host", providerURL.getHost());
            putVariable(map, "oidc.provider.path", providerURL.getPath());
            putVariable(map, "oidc.provider.protocol", providerURL.getProtocol());
            putVariable(map, "oidc.provider.port", String.valueOf(providerURL.getPort()));
        }

        // Issuer
        putVariable(map, "oidc.issuer", idToken.getIssuer().getValue());
        try {
            URI issuerURI = new URI(idToken.getIssuer().getValue());
            putVariable(map, "oidc.issuer.host", issuerURI.getHost());
            putVariable(map, "oidc.issuer.path", issuerURI.getPath());
            putVariable(map, "oidc.issuer.scheme", issuerURI.getScheme());
            putVariable(map, "oidc.issuer.port", String.valueOf(issuerURI.getPort()));
        } catch (URISyntaxException e) {
            // TODO: log something ?
        }

        StrSubstitutor substitutor = new StrSubstitutor(map);

        return substitutor.replace(this.configuration.getUserNameFormater());
    }

    public void logout()
    {
        XWikiRequest request = this.xcontextProvider.get().getRequest();

        // TODO: remove cookies

        // Make sure the session is free from anything related to a previously authenticated user (i.e. in case we are
        // just after a logout)
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_ACCESSTOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_IDTOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_USERINFO_EXPORATIONDATE);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_TOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_IDTOKENCLAIMS);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_INITIAL_REQUEST);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_XWIKIPROVIDER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_STATE);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USER_NAMEFORMATER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USERINFOCLAIMS);
    }
}
