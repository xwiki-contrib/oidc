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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.text.StringSubstitutor;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.context.concurrent.ExecutionContextRunnable;
import org.xwiki.contrib.oidc.OIDCUserInfo;
import org.xwiki.contrib.oidc.auth.OIDCLogoutException;
import org.xwiki.contrib.oidc.auth.OIDCLogoutMechanism;
import org.xwiki.contrib.oidc.auth.internal.OIDCClientConfiguration.GroupMapping;
import org.xwiki.contrib.oidc.auth.store.OIDCUserStore;
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
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
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

    private static final String XWIKI_GROUP_MEMBERFIELD = "member";

    private static final String XWIKI_GROUP_PREFIX = "XWiki.";

    public void updateUserInfoAsync() throws URISyntaxException
    {
        final Endpoint userInfoEndpoint = this.configuration.getUserInfoOIDCEndpoint();
        final IDTokenClaimsSet idToken = this.configuration.getIdToken();
        final BearerAccessToken accessToken = this.configuration.getAccessToken();

        this.executor.execute(new ExecutionContextRunnable(() -> {
            try {
                updateUserInfo(userInfoEndpoint, idToken, accessToken);
            } catch (Exception e) {
                logger.error("Failed to update user informations", e);
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

    public Principal updateUserInfo(Endpoint userInfoEndpoint, IDTokenClaimsSet idToken, BearerAccessToken accessToken)
        throws IOException, ParseException, OIDCException, XWikiException, QueryException
    {
        // Get OIDC user info
        this.logger.debug("OIDC user info request ({},{})", userInfoEndpoint, accessToken);
        UserInfoRequest userinfoRequest =
            new UserInfoRequest(userInfoEndpoint.getURI(), this.configuration.getUserInfoEndPointMethod(), accessToken);
        HTTPRequest userinfoHTTP = userinfoRequest.toHTTPRequest();
        userInfoEndpoint.prepare(userinfoHTTP);
        this.logger.debug("OIDC user info request ({}?{},{})", userinfoHTTP.getURL(), userinfoHTTP.getQuery(),
            userinfoHTTP.getHeaderMap());
        HTTPResponse httpResponse = userinfoHTTP.send();
        this.logger.debug("OIDC user info response ({})", httpResponse.getContent());
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

    private void checkAllowedGroups(UserInfo userInfo) throws OIDCException
    {
        List<String> providerGroups = null;
        Object providerGroupsObj = getClaim(this.configuration.getGroupClaim(), userInfo);
        if (this.configuration.getGroupSeparator()!=null) {
            providerGroups = Arrays.asList(StringUtils.split(providerGroupsObj.toString(), this.configuration.getGroupSeparator()));
        } else {
            providerGroups = (List<String>)providerGroupsObj;
        }
        String groupPrefix = this.configuration.getGroupPrefix();
        if (!StringUtils.isEmpty(groupPrefix)) {
            providerGroups = providerGroups.stream()
                    .filter(item -> item.startsWith(groupPrefix))
                    .map(item -> StringUtils.replace(item, groupPrefix, ""))
                    .collect(Collectors.toList());
        }
        
        if (providerGroups != null) {
            // Check allowed groups
            List<String> allowedGroups = this.configuration.getAllowedGroups();
            if (allowedGroups != null) {
                if (!CollectionUtils.containsAny(providerGroups, allowedGroups)) {
                    // Allowed groups have priority over forbidden groups
                    throw new OIDCException(
                        "The user is not allowed to authenticate because it's not a member of the following groups: "
                            + allowedGroups);
                }

                return;
            }

            // Check forbidden groups
            List<String> forbiddenGroups = this.configuration.getForbiddenGroups();
            if (forbiddenGroups != null && CollectionUtils.containsAny(providerGroups, forbiddenGroups)) {
                throw new OIDCException(
                    "The user is not allowed to authenticate because it's a member of one of the following groups: "
                        + forbiddenGroups);
            }
        }
    }

    private <T> T getClaim(String claim, ClaimsSet claims)
    {
        T value = (T) claims.getClaim(claim);

        // When it's not a proper OIDC claim try to find in a sub element of the JSON
        if (value == null) {
            value = (T) getJSONElement(claim, claims.toJSONObject());
        }

        return value;
    }

    private <T> T getJSONElement(String pattern, Map<String, ?> json)
    {
        int index = pattern.indexOf('.');

        String key;
        String patternEnd;
        if (index != -1) {
            key = pattern.substring(0, index);
            patternEnd = pattern.length() == (index + 1) ? null : pattern.substring(index + 1);
        } else {
            key = pattern;
            patternEnd = null;
        }

        Object value = json.get(key);

        if (patternEnd == null) {
            return (T) value;
        }

        if (value instanceof Map) {
            return (T) getJSONElement(patternEnd, (Map) value);
        }

        return (T) value;
    }

    public Principal updateUser(IDTokenClaimsSet idToken, UserInfo userInfo)
        throws XWikiException, QueryException, OIDCException
    {
        // Check allowed/forbidden groups
        checkAllowedGroups(userInfo);

        Map<String, String> formatMap = createFormatMap(idToken, userInfo);
        // Change the default StringSubstitutor behavior to produce an empty String instead of an unresolved pattern by
        // default
        StringSubstitutor substitutor = new StringSubstitutor(new OIDCStringLookup(formatMap));

        String formattedSubject = formatSubjec(substitutor);

        XWikiDocument userDocument = this.store.searchDocument(idToken.getIssuer().getValue(), formattedSubject);

        XWikiDocument modifiableDocument;
        boolean newUser;
        if (userDocument == null) {
            userDocument = getNewUserDocument(substitutor);

            newUser = true;
            modifiableDocument = userDocument;
        } else {
            // Don't change the document author to not change document execution right

            newUser = false;
            modifiableDocument = userDocument.clone();
        }

        XWikiContext xcontext = this.xcontextProvider.get();

        // Set user fields
        BaseClass userClass = xcontext.getWiki().getUserClass(xcontext);
        BaseObject userObject = modifiableDocument.getXObject(userClass.getDocumentReference(), true, xcontext);

        // Make sure the user is active by default
        userObject.set("active", 1, xcontext);

        // Address
        Address address = userInfo.getAddress();
        if (address != null) {
            userObject.set("address", address.getFormatted(), xcontext);
        }

        // Email
        if (userInfo.getEmailAddress() != null) {
            userObject.set("email", userInfo.getEmailAddress(), xcontext);
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
                    modifiableDocument.setAttachment(filename, content, xcontext);
                }
                userObject.set("avatar", filename, xcontext);
            } catch (IOException e) {
                this.logger.warn("Failed to get user avatar from URL [{}]: {}", userInfo.getPicture(),
                    ExceptionUtils.getRootCauseMessage(e));
            }
        }

        // XWiki claims
        updateXWikiClaims(modifiableDocument, userClass, userObject, userInfo, xcontext);

        // Set OIDC fields
        this.store.updateOIDCUser(modifiableDocument, idToken.getIssuer().getValue(), formattedSubject);

        // Configured user mapping
        updateUserMapping(modifiableDocument, userClass, userObject, xcontext, substitutor);

        // Data to send with the event
        OIDCUserEventData eventData =
            new OIDCUserEventData(new NimbusOIDCIdToken(idToken), new NimbusOIDCUserInfo(userInfo));

        // Notify
        this.observation.notify(new OIDCUserUpdating(modifiableDocument.getDocumentReference()), modifiableDocument,
            eventData);

        boolean userUpdated = false;

        // Apply the modifications
        if (newUser || userDocument.apply(modifiableDocument)) {
            String comment;
            if (newUser) {
                comment = "Create user from OpenID Connect";
            } else {
                comment = "Update user from OpenID Connect";
            }

            xcontext.getWiki().saveDocument(userDocument, comment, xcontext);

            // Now let's add the new user to XWiki.XWikiAllGroup
            if (newUser) {
                xcontext.getWiki().setUserDefaultGroup(userDocument.getFullName(), xcontext);
            }

            userUpdated = true;
        }

        // Sync user groups with the provider
        if (this.configuration.isGroupSync()) {
            userUpdated = updateGroupMembership(userInfo, userDocument, xcontext);
        }

        // Notify
        if (userUpdated) {
            this.observation.notify(new OIDCUserUpdated(userDocument.getDocumentReference()), userDocument, eventData);
        }

        return new SimplePrincipal(userDocument.getPrefixedFullName());
    }

    private void updateUserMapping(XWikiDocument userDocument, BaseClass userClass, BaseObject userObject,
        XWikiContext xcontext, StringSubstitutor substitutor)
    {
        Map<String, String> mapping = this.configuration.getUserMapping();
        if (mapping != null) {
            for (Map.Entry<String, String> entry : mapping.entrySet()) {
                String xwikiProperty = entry.getKey();
                String oidcFormat = entry.getValue();

                String oidcValue = substitutor.replace(oidcFormat);

                setValue(userDocument, userClass, userObject, xwikiProperty, oidcValue, xcontext);
            }
        }
    }

    private boolean updateGroupMembership(UserInfo userInfo, XWikiDocument userDocument, XWikiContext xcontext)
        throws XWikiException
    {
        String groupClaim = this.configuration.getGroupClaim();

        this.logger.debug("Getting groups sent by the provider associated with claim [{}]", groupClaim);

        List<String> providerGroups = null;
        Object providerGroupsObj = getClaim(this.configuration.getGroupClaim(), userInfo);
        if (this.configuration.getGroupSeparator()!=null) {
            providerGroups = Arrays.asList(StringUtils.split(providerGroupsObj.toString(), this.configuration.getGroupSeparator()));
        } else {
            providerGroups = (List<String>)providerGroupsObj;
        }
        String groupPrefix = this.configuration.getGroupPrefix();
        if (!StringUtils.isEmpty(groupPrefix)) {
            providerGroups = providerGroups.stream()
                    .filter(item -> item.startsWith(groupPrefix))
                    .map(item -> StringUtils.replace(item, groupPrefix, ""))
                    .collect(Collectors.toList());
        }
        
        if (providerGroups != null) {
            this.logger.debug("The provider sent the following groups: {}", providerGroups);

            return syncXWikiGroupsMembership(userDocument.getFullName(), providerGroups, xcontext);
        } else {
            this.logger.debug("The provider did not sent any group");
        }

        return false;
    }

    /**
     * Remove user name from provided XWiki group.
     *
     * @param xwikiUserName the full name of the user.
     * @param xwikiGroupName the name of the group.
     * @param context the XWiki context.
     */
    protected void removeUserFromXWikiGroup(String xwikiUserName, String xwikiGroupName, XWikiContext context)
    {
        this.logger.debug("Removing user from [{}] ...", xwikiGroupName);

        try {
            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get the XWiki document holding the objects comprising the group membership list
            XWikiDocument groupDoc = context.getWiki().getDocument(xwikiGroupName, context);

            synchronized (groupDoc) {
                // Get and remove the specific group membership object for the user
                BaseObject groupObj =
                    groupDoc.getXObject(groupClass.getDocumentReference(), XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                groupDoc.removeXObject(groupObj);

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }
        } catch (Exception e) {
            this.logger.error("Failed to remove user [{}] from group [{}]", xwikiUserName, xwikiGroupName, e);
        }
    }

    /**
     * Add user name into provided XWiki group.
     *
     * @param xwikiUserName the full name of the user.
     * @param xwikiGroupName the name of the group.
     * @param context the XWiki context.
     */
    protected void addUserToXWikiGroup(String xwikiUserName, String xwikiGroupName, XWikiContext context)
    {
        try {
            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get document representing group
            XWikiDocument groupDoc = context.getWiki().getDocument(xwikiGroupName, context);

            this.logger.debug("Adding user [{}] to xwiki group [{}]", xwikiUserName, xwikiGroupName);

            synchronized (groupDoc) {
                // Make extra sure the group cannot contain duplicate (even if this method is not supposed to be called
                // in this case)
                List<BaseObject> xobjects = groupDoc.getXObjects(groupClass.getDocumentReference());
                if (xobjects != null) {
                    for (BaseObject memberObj : xobjects) {
                        if (memberObj != null) {
                            String existingMember = memberObj.getStringValue(XWIKI_GROUP_MEMBERFIELD);
                            if (existingMember != null && existingMember.equals(xwikiUserName)) {
                                this.logger.warn("User [{}] already exist in group [{}]", xwikiUserName,
                                    groupDoc.getDocumentReference());
                                return;
                            }
                        }
                    }
                }

                // Add a member object to document
                BaseObject memberObj = groupDoc.newXObject(groupClass.getDocumentReference(), context);
                Map<String, String> map = new HashMap<>();
                map.put(XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                groupClass.fromMap(map, memberObj);

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }

            this.logger.debug("Finished adding user [{}] to xwiki group [{}]", xwikiUserName, xwikiGroupName);
        } catch (Exception e) {
            this.logger.error("Failed to add a user [{}] to a group [{}]", xwikiUserName, xwikiGroupName, e);
        }
    }

    /**
     * Synchronize user XWiki membership with the Open ID xwiki_groups claim.
     *
     * @param xwikiUserName the name of the user.
     * @param providerGroups the Open ID xwiki_groups claim.
     * @param context the XWiki context.
     * @throws XWikiException error when synchronizing user membership.
     */
    public Boolean syncXWikiGroupsMembership(String xwikiUserName, List<String> providerGroups, XWikiContext context)
        throws XWikiException
    {
        Boolean userUpdated = false;
        this.logger.debug("Updating group membership for the user [{}]", xwikiUserName);

        Collection<String> xwikiUserGroupList =
            context.getWiki().getGroupService(context).getAllGroupsNamesForMember(xwikiUserName, 0, 0, context);

        this.logger.debug("The user belongs to following XWiki groups: {}", xwikiUserGroupList);

        GroupMapping groupMapping = this.configuration.getGroupMapping();

        // Add missing group membership
        for (String providerGroupName : providerGroups) {
            if (groupMapping == null) {
                String xwikiGroup = this.configuration.toXWikiGroup(providerGroupName);
                if (!xwikiUserGroupList.contains(xwikiGroup)) {
                    addUserToXWikiGroup(xwikiUserName, xwikiGroup, context);
                    userUpdated = true;
                }
            } else {
                Set<String> mappedGroups = groupMapping.fromProvider(providerGroupName);
                if (mappedGroups != null) {
                    for (String mappedGroup : mappedGroups) {
                        if (!xwikiUserGroupList.contains(mappedGroup)) {
                            addUserToXWikiGroup(xwikiUserName, mappedGroup, context);
                            userUpdated = true;
                        }
                    }
                }
            }
        }

        // Remove group membership
        for (String xwikiGroupName : xwikiUserGroupList) {
            if (groupMapping == null) {
                if (!providerGroups.contains(xwikiGroupName)
                    && !providerGroups.contains(xwikiGroupName.substring(XWIKI_GROUP_PREFIX.length()))) {
                    removeUserFromXWikiGroup(xwikiUserName, xwikiGroupName, context);
                    userUpdated = true;
                }
            } else {
                Set<String> mappedGroups = groupMapping.fromXWiki(xwikiGroupName);
                if (mappedGroups != null && !CollectionUtils.containsAny(providerGroups, mappedGroups)) {
                    removeUserFromXWikiGroup(xwikiUserName, xwikiGroupName, context);
                    userUpdated = true;
                }
            }
        }

        return userUpdated;

    }

    private void updateXWikiClaims(XWikiDocument userDocument, BaseClass userClass, BaseObject userObject,
        UserInfo userInfo, XWikiContext xcontext)
    {
        this.logger.debug("Updating XWiki claims");
        for (Map.Entry<String, Object> entry : userInfo.toJSONObject().entrySet()) {
            if (entry.getKey().startsWith(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER)) {
                String xwikiKey = entry.getKey().substring(OIDCUserInfo.CLAIMPREFIX_XWIKI_USER.length());

                setValue(userDocument, userClass, userObject, xwikiKey, entry.getValue(), xcontext);
            }
        }
    }

    private void setValue(XWikiDocument userDocument, BaseClass userClass, BaseObject userObject, String xwikiKey,
        Object value, XWikiContext xcontext)
    {
        // Try in the user object
        if (userClass.getField(xwikiKey) != null) {
            setValue(userObject, xwikiKey, value, xcontext);

            return;
        }

        // Try in the whole user document
        BaseObject xobject = userDocument.getFirstObject(xwikiKey);
        if (xobject != null) {
            setValue(xobject, xwikiKey, value, xcontext);
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

    private XWikiDocument getNewUserDocument(StringSubstitutor substitutor) throws XWikiException
    {
        XWikiContext xcontext = this.xcontextProvider.get();

        // TODO: add support for subwikis
        SpaceReference spaceReference = new SpaceReference(xcontext.getMainXWiki(), "XWiki");

        // Generate default document name
        String documentName = formatXWikiUserName(substitutor);

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
        return RegExUtils.removePattern(str, "[\\.\\:\\s,@\\^]");
    }

    private void putVariable(Map<String, String> map, String key, String value)
    {
        if (value != null) {
            map.put(key, value);

            map.put(key + ".lowerCase", value.toLowerCase());
            map.put(key + "._lowerCase", value.toLowerCase());
            map.put(key + ".upperCase", value.toUpperCase());
            map.put(key + "._upperCase", value.toUpperCase());

            String cleanValue = clean(value);
            map.put(key + ".clean", cleanValue);
            map.put(key + "._clean", cleanValue);
            map.put(key + ".clean.lowerCase", cleanValue.toLowerCase());
            map.put(key + "._clean._lowerCase", cleanValue.toLowerCase());
            map.put(key + ".clean.upperCase", cleanValue.toUpperCase());
            map.put(key + "._clean._upperCase", cleanValue.toUpperCase());
        }
    }

    private Map<String, String> createFormatMap(IDTokenClaimsSet idToken, UserInfo userInfo)
    {
        Map<String, String> formatMap = new HashMap<>();

        // User informations
        putVariable(formatMap, "oidc.user.subject", userInfo.getSubject().getValue());
        if (userInfo.getPreferredUsername() != null) {
            putVariable(formatMap, "oidc.user.preferredUsername", userInfo.getPreferredUsername());
        } else {
            putVariable(formatMap, "oidc.user.preferredUsername", userInfo.getSubject().getValue());
        }
        putVariable(formatMap, "oidc.user.mail", userInfo.getEmailAddress() == null ? "" : userInfo.getEmailAddress());
        putVariable(formatMap, "oidc.user.familyName", userInfo.getFamilyName());
        putVariable(formatMap, "oidc.user.givenName", userInfo.getGivenName());

        // Provider (only XWiki OIDC providers)
        URL providerURL = this.configuration.getXWikiProvider();
        if (providerURL != null) {
            putVariable(formatMap, "oidc.provider", providerURL.toString());
            putVariable(formatMap, "oidc.provider.host", providerURL.getHost());
            putVariable(formatMap, "oidc.provider.path", providerURL.getPath());
            putVariable(formatMap, "oidc.provider.protocol", providerURL.getProtocol());
            putVariable(formatMap, "oidc.provider.port", String.valueOf(providerURL.getPort()));
        }

        // Issuer
        putVariable(formatMap, "oidc.issuer", idToken.getIssuer().getValue());
        try {
            URI issuerURI = new URI(idToken.getIssuer().getValue());
            putVariable(formatMap, "oidc.issuer.host", issuerURI.getHost());
            putVariable(formatMap, "oidc.issuer.path", issuerURI.getPath());
            putVariable(formatMap, "oidc.issuer.scheme", issuerURI.getScheme());
            putVariable(formatMap, "oidc.issuer.port", String.valueOf(issuerURI.getPort()));
        } catch (URISyntaxException e) {
            // TODO: log something ?
        }

        // Inject the whole JSON
        addJSON("oidc.user.", userInfo.toJSONObject(), formatMap);

        return formatMap;
    }

    private void addJSON(String prefix, Map<String, ?> json, Map<String, String> formatMap)
    {
        for (Map.Entry<String, ?> entry : json.entrySet()) {
            if (entry.getValue() != null) {
                if (entry.getValue() instanceof Map) {
                    addJSON(prefix + entry.getKey() + '.', (Map) entry.getValue(), formatMap);
                } else {
                    putVariable(formatMap, prefix + entry.getKey(), entry.getValue().toString());
                }
            }
        }
    }

    private String formatXWikiUserName(StringSubstitutor substitutor)
    {
        return substitutor.replace(this.configuration.getXWikiUserNameFormater());
    }

    private String formatSubjec(StringSubstitutor substitutor)
    {
        return substitutor.replace(this.configuration.getSubjectFormater());
    }

    public void logout()
    {
        XWikiRequest request = this.xcontextProvider.get().getRequest();

        // Try first to load the configured logout mechanism
        String logoutMechanismHint = this.configuration.getLogoutMechanism();
        OIDCLogoutMechanism logoutMechanism = prepareLogoutMechanism(logoutMechanismHint);
        if (logoutMechanism == null) {
            prepareLogoutMechanism(OIDCClientConfiguration.DEFAULT_LOGOUT_MECHANISM);
        }

        // Make sure the session is free from anything related to a previously authenticated user (i.e. in case we are
        // just after a logout)
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_ACCESSTOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_SESSION_IDTOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_AUTHORIZATION);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_TOKEN);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_ENDPOINT_USERINFO);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_IDTOKENCLAIMS);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_INITIAL_REQUEST);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_XWIKIPROVIDER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_STATE);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USER_NAMEFORMATER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USER_SUBJECTFORMATER);
        request.getSession().removeAttribute(OIDCClientConfiguration.PROP_USERINFOCLAIMS);

        // Destroy the session. Taken from LogoutAction
        HttpSession currentSession = request.getSession();
        if (currentSession != null ){
            synchronized (currentSession) {
                currentSession.invalidate();

                // Early registration of a new session, so that the client gets to know the new session identifier early
                // A new session is going to be needed after the redirect anyway
                request.getSession(true);
            }
        }

        if (logoutMechanism != null) {
            try {
                logoutMechanism.logout();
            } catch (OIDCLogoutException e) {
                this.logger.error("Failed to run OIDC log-out", e);
            }
        }
    }

    private OIDCLogoutMechanism prepareLogoutMechanism(String hint)
    {
        OIDCLogoutMechanism logoutMechanism = null;

        try {
            if (componentManager.hasComponent(OIDCLogoutMechanism.class, hint)) {
                logoutMechanism = componentManager.getInstance(OIDCLogoutMechanism.class, hint);
                logoutMechanism.prepareLogout();
            } else {
                this.logger.warn("OIDC Log-out mechanism not found with hint [{}]", hint);
            }
        } catch (ComponentLookupException e) {
            this.logger.error("Failed to load OIDC log-out mechanism [{}]", hint);
        } catch (OIDCLogoutException e) {
            this.logger.error("Failed to prepare for OIDC log-out with mechanism [{}].", hint);
        }

        return logoutMechanism;
    }
}
