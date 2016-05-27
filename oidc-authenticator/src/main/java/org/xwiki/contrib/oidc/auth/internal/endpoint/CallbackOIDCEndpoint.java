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
package org.xwiki.contrib.oidc.auth.internal.endpoint;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration;
import org.xwiki.contrib.oidc.auth.internal.store.OIDCUserStore;
import org.xwiki.contrib.oidc.provider.internal.OIDCException;
import org.xwiki.contrib.oidc.provider.internal.OIDCResourceReference;
import org.xwiki.contrib.oidc.provider.internal.endpoint.OIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.util.RedirectResponse;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.query.QueryException;

import com.google.common.base.Objects;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.user.api.XWikiRightService;

/**
 * Token endpoint for OpenId Connect.
 * 
 * @version $Id$
 */
@Component
@Named(CallbackOIDCEndpoint.HINT)
@Singleton
public class CallbackOIDCEndpoint implements OIDCEndpoint
{
    /**
     * The endpoint name.
     */
    public static final String HINT = "authenticator/callback";

    @Inject
    private Container container;

    @Inject
    private Provider<XWikiContext> xcontextProvider;

    @Inject
    private OIDCClientConfiguration configuration;

    @Inject
    private OIDCUserStore store;

    @Inject
    private Logger logger;

    @Override
    public Response handle(HTTPRequest httpRequest, OIDCResourceReference reference) throws Exception
    {
        // Parse the request
        AuthenticationSuccessResponse authorizationResponse = AuthenticationSuccessResponse.parse(httpRequest);

        // Validate state
        State state = authorizationResponse.getState();
        if (!Objects.equal(state, this.configuration.getSessionState())) {
            throw new OIDCException("Invalid state [" + state + "]");
        }

        // Get authorization code
        AuthorizationCode code = authorizationResponse.getAuthorizationCode();

        // Get access token
        AuthorizationGrant authorizationGrant =
            new AuthorizationCodeGrant(code, authorizationResponse.getRedirectionURI());
        // TODO: setup some client authentication, secret, all that
        TokenRequest tokeRequest = new TokenRequest(this.configuration.getTokenOIDCEndpoint(),
            new ClientID(this.configuration.getClientID()), authorizationGrant);
        HTTPRequest tokenHTTP = tokeRequest.toHTTPRequest();
        tokenHTTP.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
            + this.getClass().getPackage().getImplementationVersion());
        HTTPResponse httpResponse = tokenHTTP.send();
        TokenResponse tokenResponse = TokenResponse.parse(httpResponse);

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse error = (TokenErrorResponse) tokenResponse;
            throw new OIDCException("Failed to get access token", error.getErrorObject());
        }

        AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;
        BearerAccessToken accessToken = accessTokenResponse.getTokens().getBearerAccessToken();

        // Get OIDC user info
        UserInfoRequest userinfoRequest =
            new UserInfoRequest(this.configuration.getUserInfoOIDCEndpoint(), accessToken);
        HTTPRequest userinfoHTTP = userinfoRequest.toHTTPRequest();
        userinfoHTTP.setHeader("User-Agent", this.getClass().getPackage().getImplementationTitle() + '/'
            + this.getClass().getPackage().getImplementationVersion());
        httpResponse = userinfoHTTP.send();
        UserInfoResponse userinfoResponse = UserInfoResponse.parse(httpResponse);

        if (!userinfoResponse.indicatesSuccess()) {
            UserInfoErrorResponse error = (UserInfoErrorResponse) userinfoResponse;
            throw new OIDCException("Failed to get user info", error.getErrorObject());
        }

        UserInfoSuccessResponse userinfoSuccessResponse = (UserInfoSuccessResponse) userinfoResponse;
        UserInfo userInfo = userinfoSuccessResponse.getUserInfo();

        // Update/Create XWiki user
        Principal principal = updateUser(userInfo);

        // Remember user in the session
        HttpSession session = ((ServletSession) this.container.getSession()).getHttpSession();
        session.setAttribute(SecurityRequestWrapper.PRINCIPAL_SESSION_KEY, principal);

        // Redirect to original request
        return new RedirectResponse(new URI(authorizationResponse.getState().getValue()));
    }

    private Principal updateUser(UserInfo userInfo) throws XWikiException, QueryException, URISyntaxException
    {
        XWikiDocument document =
            this.store.searchDocument(this.configuration.getProvider().toString(), userInfo.getSubject().toString());

        boolean newUser;
        if (document == null) {
            document = getNewUserDocument(userInfo);
            newUser = true;
        } else {
            // Don't change the document author to not change document execution right

            newUser = false;
        }

        XWikiContext xcontext = this.xcontextProvider.get();

        boolean needSave = newUser;

        // Set user fields
        BaseObject originalUserObject =
            document.getXObject(xcontext.getWiki().getUserClass(xcontext).getDocumentReference(), true, xcontext);

        BaseObject userObject = originalUserObject.clone();

        // TODO: Time Zone
        if (userInfo.getZoneinfo() != null) {
            userInfo.getZoneinfo();
        }

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

        // TODO: Avatar
        if (userInfo.getPicture() != null) {
            userInfo.getPicture();
        }

        needSave |= originalUserObject.apply(userObject, false);

        // Set OIDC fields
        needSave |= this.store.updateOIDCUser(document, this.configuration.getProvider().toString(),
            userInfo.getSubject().getValue());

        // Save the document
        if (needSave) {
            String comment;
            if (document.isNew()) {
                comment = "Create user from OpenId Connect";
            } else {
                comment = "Update user from OpenId Connect";
            }

            xcontext.getWiki().saveDocument(document, comment, xcontext);

            // Now let's add new the user to XWiki.XWikiAllGroup
            if (newUser) {
                xcontext.getWiki().setUserDefaultGroup(document.getFullName(), xcontext);
            }
        }

        return new SimplePrincipal(document.getPrefixedFullName());
    }

    private XWikiDocument getNewUserDocument(UserInfo userInfo) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        // TODO: add support for subwikis
        SpaceReference spaceReference = new SpaceReference(xcontext.getMainXWiki(), "XWiki");

        // Generate default document name
        String documentName = formatUserName(userInfo);

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

    private String formatUserName(UserInfo userInfo)
    {
        Map<String, String> map = new HashMap<>();

        putVariable(map, "oidc.subject", userInfo.getSubject().getValue());

        URL providerURL = this.configuration.getProvider();
        putVariable(map, "oidc.provider.url", providerURL.toString());
        putVariable(map, "oidc.provider.host", providerURL.getHost());
        putVariable(map, "oidc.provider.path", providerURL.getPath());

        map.put("oidc.provider.protocol", providerURL.getProtocol());
        map.put("oidc.provider.port", String.valueOf(providerURL.getPort()));

        StrSubstitutor substitutor = new StrSubstitutor(map);

        return substitutor.replace(this.configuration.getUserNameFormater());
    }
}
