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
package org.xwiki.contrib.oidc.auth.store;

import java.util.Arrays;
import java.util.List;

import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Helper wrapping a BaseObject to make easier to manipulate OIDC client configuration.
 *
 * @version $Id$
 * @since 1.30
 */
public class OIDCClientConfiguration
{
    /**
     * The String reference of the class defining the object which contains an OIDC configuration.
     */
    public static final String CLASS_FULLNAME = "XWiki.OIDC.ClientConfigurationClass";

    /**
     * The local reference of the configuration class.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "ClientConfigurationClass");

    /**
     * Name of the property containing the configuration.
     */
    public static final String FIELD_CONFIGURATION_NAME = "configurationName";

    /**
     * Name of the property containing the groups claim.
     */
    public static final String FIELD_CLAIM_GROUP = "groupsClaim";

    /**
     * Name of the property containing the group mappings.
     */
    public static final String FIELD_GROUP_MAPPING = "groupsMapping";

    /**
     * Name of the property containing the allowed groups.
     */
    public static final String FIELD_ALLOWED_GROUPS = "allowedGroups";

    /**
     * Name of the property containing the forbidden groups.
     */
    public static final String FIELD_FORBIDDEN_GROUPS = "forbiddenGroups";

    /**
     * Name of the property containing the ID token claims.
     */
    public static final String FIELD_CLAIMS_ID_TOKEN = "idTokenClaims";

    /**
     * Name of the property containing the user info claims.
     */
    public static final String FIELD_CLAIMS_USER_INFO = "userInfoClaims";

    /**
     * Name of the property containing the user name formatter.
     */
    public static final String FIELD_FORMATTER_USER_NAME = "userNameFormatter";

    /**
     * Name of the property containing the user subject formatter.
     */
    public static final String FIELD_FORMATTER_USER_SUBJECT = "userSubjectFormatter";

    /**
     * Name of the property containing the user mapping.
     */
    public static final String FIELD_USER_MAPPING = "userMapping";

    /**
     * Name of the property containing the XWiki provider.
     */
    public static final String FIELD_XWIKI_PROVIDER = "xwikiProvider";

    /**
     * Name of the property containing the authorization endpoint.
     */
    public static final String FIELD_ENDPOINT_AUTHORIZATION = "authorizationEndpoint";

    /**
     * Name of the property containing the token endpoint.
     */
    public static final String FIELD_ENDPOINT_TOKEN = "tokenEndpoint";

    /**
     * Name of the property containing the user info endpoint.
     */
    public static final String FIELD_ENDPOINT_USERINFO = "userInfoEndpoint";

    /**
     * Name of the property containing the logout endpoint.
     */
    public static final String FIELD_ENDPOINT_LOGOUT = "logoutEndpoint";

    /**
     * Name of the property containing the token endpoint method.
     */
    public static final String FIELD_ENDPOINT_TOKEN_METHOD = "tokenEndpointMethod";

    /**
     * Name of the property containing the user info endpoint method.
     */
    public static final String FIELD_ENDPOINT_USERINFO_METHOD = "userInfoEndpointMethod";

    /**
     * Name of the property containing the user info endpoint headers.
     */
    public static final String FIELD_ENDPOINT_USERINFO_HEADERS = "userInfoEndpointHeaders";

    /**
     * Name of the property containing the logout endpoint method.
     */
    public static final String FIELD_ENDPOINT_LOGOUT_METHOD = "logoutEndpointMethod";

    /**
     * Name of the property containing the token to use to register the client.
     * 
     * @since 2.4.0
     */
    public static final String FIELD_ENDPOINT_REGISTER_TOKEN = "registerEndpointToken";

    /**
     * Name of the property containing the client id.
     */
    public static final String FIELD_CLIENT_ID = "clientId";

    /**
     * Name of the property containing the client secret.
     */
    public static final String FIELD_CLIENT_SECRET = "clientSecret";

    /**
     * Name of the property indicating if this client configuration should be skipped.
     */
    public static final String FIELD_SKIPPED = "skipped";

    /**
     * Name of the property containing the scope.
     */
    public static final String FIELD_SCOPE = "scope";

    /**
     * Name of the property containing the scope.
     * 
     * @since 2.7.0
     */
    public static final String FIELD_RESPONSE_TYPE = "responseType";

    /**
     * Name of the property containing the user info refresh rate.
     */
    public static final String FIELD_USER_INFO_REFRESH_RATE = "userInfoRefreshRate";

    /**
     * The name of the logout mechanism to be used.
     * 
     * @since 1.31
     */
    public static final String FIELD_LOGOUT_MECHANISM = "logoutMechanism";

    /**
     * The name of the property defining if users should be enabled by default or not.
     *
     * @since 2.5.0
     */
    public static final String FIELD_ENABLE_USER = "enableUser";

    private static final String LIST_SPLIT_REGEX = "(\\r?\\n|,|\\|)";

    private static final String JOIN_CHAR = "\n";

    private final BaseObject xobject;

    /**
     * @param xobject the actual XWiki object
     */
    public OIDCClientConfiguration(BaseObject xobject)
    {
        this.xobject = xobject;
    }

    /**
     * @return the configuration name
     */
    public String getConfigurationName()
    {
        return this.xobject.getStringValue(FIELD_CONFIGURATION_NAME);
    }

    /**
     * @param configurationName the configuration name
     */
    public void setConfigurationName(String configurationName)
    {
        this.xobject.setStringValue(FIELD_CONFIGURATION_NAME, configurationName);
    }

    /**
     * @return the group claim
     */
    public String getGroupClaim()
    {
        return this.xobject.getStringValue(FIELD_CLAIM_GROUP);
    }

    /**
     * @param groupClaim the group claim
     */
    public void setGroupClaim(String groupClaim)
    {
        this.xobject.setStringValue(FIELD_CLAIM_GROUP, groupClaim);
    }

    /**
     * @return the group mapping
     */
    public List<String> getGroupMapping()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_GROUP_MAPPING).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param groupMapping the group mapping
     */
    public void setGroupMapping(List<String> groupMapping)
    {
        this.xobject.setLargeStringValue(FIELD_GROUP_MAPPING, String.join(JOIN_CHAR, groupMapping));
    }

    /**
     * @return the allowed groups
     */
    public List<String> getAllowedGroups()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_ALLOWED_GROUPS).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param allowedGroups the allowed groups
     */
    public void setAllowedGroups(List<String> allowedGroups)
    {
        this.xobject.setLargeStringValue(FIELD_ALLOWED_GROUPS, String.join(JOIN_CHAR, allowedGroups));
    }

    /**
     * @return the forbidden groups
     */
    public List<String> getForbiddenGroups()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_FORBIDDEN_GROUPS).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param forbiddenGroups the forbidden groups
     */
    public void setForbiddenGroups(List<String> forbiddenGroups)
    {
        this.xobject.setLargeStringValue(FIELD_FORBIDDEN_GROUPS, String.join(JOIN_CHAR, forbiddenGroups));
    }

    /**
     * @return the user subject formatter
     */
    public String getUserSubjectFormatter()
    {
        return this.xobject.getStringValue(FIELD_FORMATTER_USER_SUBJECT);
    }

    /**
     * @param userSubjectFormatter the user subject formatter
     */
    public void setUserSubjectFormatter(String userSubjectFormatter)
    {
        this.xobject.setStringValue(FIELD_FORMATTER_USER_SUBJECT, userSubjectFormatter);
    }

    /**
     * @return the user name formatter
     */
    public String getUserNameFormatter()
    {
        return this.xobject.getStringValue(FIELD_FORMATTER_USER_NAME);
    }

    /**
     * @param userNameFormatter the user name formatter
     */
    public void setUserNameFormatter(String userNameFormatter)
    {
        this.xobject.setStringValue(FIELD_FORMATTER_USER_NAME, userNameFormatter);
    }

    /**
     * @return the user mapping
     */
    public List<String> getUserMapping()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_USER_MAPPING).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param userMapping the user mapping
     */
    public void setUserMapping(List<String> userMapping)
    {
        this.xobject.setLargeStringValue(FIELD_USER_MAPPING, String.join(JOIN_CHAR, userMapping));
    }

    /**
     * @return the XWiki provider
     */
    public String getXWikiProvider()
    {
        return this.xobject.getStringValue(FIELD_XWIKI_PROVIDER);
    }

    /**
     * @param xwikiProvider the XWiki provider
     */
    public void setXWikiProvider(String xwikiProvider)
    {
        this.xobject.setStringValue(FIELD_XWIKI_PROVIDER, xwikiProvider);
    }

    /**
     * @return the authorization endpoint
     */
    public String getAuthorizationEndpoint()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_AUTHORIZATION);
    }

    /**
     * @param authorizationEndpoint the authorization endpoint
     */
    public void setAuthorizationEndpoint(String authorizationEndpoint)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_AUTHORIZATION, authorizationEndpoint);
    }

    /**
     * @return the token endpoint
     */
    public String getTokenEndpoint()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_TOKEN);
    }

    /**
     * @param tokenEndpoint the token endpoint
     */
    public void setTokenEndpoint(String tokenEndpoint)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_TOKEN, tokenEndpoint);
    }

    /**
     * @return the user info endpoint
     */
    public String getUserInfoEndpoint()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_USERINFO);
    }

    /**
     * @param userInfoEndpoint the user info endpoint
     */
    public void setUserInfoEndpoint(String userInfoEndpoint)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_USERINFO, userInfoEndpoint);
    }

    /**
     * @return the logout endpoint
     */
    public String getLogoutEndpoint()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_LOGOUT);
    }

    /**
     * @param logoutEndpoint the logout endpoint
     */
    public void setLogoutEndpoint(String logoutEndpoint)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_LOGOUT, logoutEndpoint);
    }

    /**
     * @return the client id
     */
    public String getClientId()
    {
        return this.xobject.getStringValue(FIELD_CLIENT_ID);
    }

    /**
     * @param clientId the client id
     */
    public void setClientId(String clientId)
    {
        this.xobject.setStringValue(FIELD_CLIENT_ID, clientId);
    }

    /**
     * @return the client secret
     */
    public String getClientSecret()
    {
        return this.xobject.getStringValue(FIELD_CLIENT_SECRET);
    }

    /**
     * @param clientSecret the client secret
     */
    public void setClientSecret(String clientSecret)
    {
        this.xobject.setStringValue(FIELD_CLIENT_SECRET, clientSecret);
    }

    /**
     * @return the token endpoint method
     */
    public String getTokenEndpointMethod()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_TOKEN_METHOD);
    }

    /**
     * @param tokenEndpointMethod the token endpoint method
     */
    public void setTokenEndpointMethod(String tokenEndpointMethod)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_TOKEN_METHOD, tokenEndpointMethod);
    }

    /**
     * @return the user info endpoint method
     */
    public String getUserInfoEndpointMethod()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_USERINFO_METHOD);
    }

    /**
     * @param userInfoEndpointMethod the user info endpoint method
     */
    public void setUserInfoEndpointMethod(String userInfoEndpointMethod)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_USERINFO_METHOD, userInfoEndpointMethod);
    }

    /**
     * @return the user info endpoint headers
     */
    public List<String> getUserInfoEndpointHeaders()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_ENDPOINT_USERINFO_HEADERS).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param userInfoEndpointHeaders the user info endpoint headers
     */
    public void setUserInfoEndpointHeaders(List<String> userInfoEndpointHeaders)
    {
        this.xobject.setLargeStringValue(FIELD_ENDPOINT_USERINFO_HEADERS,
            String.join(JOIN_CHAR, userInfoEndpointHeaders));
    }

    /**
     * @return the logout endpoint method
     */
    public String getLogoutEndpointMethod()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_LOGOUT_METHOD);
    }

    /**
     * @param logoutEndpointMethod the logout endpoint method
     */
    public void setLogoutEndpointMethod(String logoutEndpointMethod)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_LOGOUT_METHOD, logoutEndpointMethod);
    }

    /**
     * @return the register endpoint token
     * @since 2.4.0
     */
    public String getRegisterEndpointToken()
    {
        return this.xobject.getStringValue(FIELD_ENDPOINT_REGISTER_TOKEN);
    }

    /**
     * @param registerEndpointToken the register endpoint token
     * @since 2.4.0
     */
    public void setRegisterEndpointToken(String registerEndpointToken)
    {
        this.xobject.setStringValue(FIELD_ENDPOINT_REGISTER_TOKEN, registerEndpointToken);
    }

    /**
     * @return true if the client configuration should be skipped
     */
    public boolean isSkipped()
    {
        return (this.xobject.getIntValue(FIELD_SKIPPED) == 1);
    }

    /**
     * @param isSkipped whether the client configuration should be skipped
     */
    public void setIsSkipped(boolean isSkipped)
    {
        this.xobject.setIntValue(FIELD_SKIPPED, (isSkipped) ? 1 : 0);
    }

    /**
     * @return the scope
     */
    public List<String> getScope()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_SCOPE).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param scope the scope
     */
    public void setScope(List<String> scope)
    {
        this.xobject.setLargeStringValue(FIELD_SCOPE, String.join(JOIN_CHAR, scope));
    }

    /**
     * @return the response type
     * @since 2.7.0
     */
    public List<String> getResponseType()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_RESPONSE_TYPE).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param responseType the response type
     * @since 2.7.0
     */
    public void setResponseType(List<String> responseType)
    {
        this.xobject.setLargeStringValue(FIELD_RESPONSE_TYPE, String.join(JOIN_CHAR, responseType));
    }

    /**
     * @return the id token claims
     */
    public List<String> getIdTokenClaims()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_CLAIMS_ID_TOKEN).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param idTokenClaims the id token claims
     */
    public void setIdTokenClaims(List<String> idTokenClaims)
    {
        this.xobject.setLargeStringValue(FIELD_CLAIMS_ID_TOKEN, String.join(JOIN_CHAR, idTokenClaims));
    }

    /**
     * @return the user info claims
     */
    public List<String> getUserInfoClaims()
    {
        return Arrays.asList(this.xobject.getLargeStringValue(FIELD_CLAIMS_USER_INFO).split(LIST_SPLIT_REGEX));
    }

    /**
     * @param userInfoClaims the user info claims
     */
    public void setUserInfoClaims(List<String> userInfoClaims)
    {
        this.xobject.setLargeStringValue(FIELD_CLAIMS_USER_INFO, String.join(JOIN_CHAR, userInfoClaims));
    }

    /**
     * @return the user info refresh rate
     */
    public Integer getUserInfoRefreshRate()
    {
        return this.xobject.getIntValue(FIELD_USER_INFO_REFRESH_RATE);
    }

    /**
     * @param userInfoRefreshRate the user info refresh rate
     */
    public void setUserInfoRefreshRate(int userInfoRefreshRate)
    {
        this.xobject.setIntValue(FIELD_USER_INFO_REFRESH_RATE, userInfoRefreshRate);
    }

    /**
     * @return the logout mechanism
     * @since 1.31
     */
    public String getLogoutMechanism()
    {
        return this.xobject.getStringValue(FIELD_LOGOUT_MECHANISM);
    }

    /**
     * @param logoutMechanism the logout mechanism
     * @since 1.31
     */
    public void setLogoutMechanism(String logoutMechanism)
    {
        this.xobject.setStringValue(FIELD_LOGOUT_MECHANISM, logoutMechanism);
    }

    /**
     * @return true if the user should be enabled at creation
     * @since 2.5.0
     */
    public boolean getEnableUser()
    {
        return (this.xobject.getIntValue(FIELD_ENABLE_USER, 1) == 1);
    }

    /**
     * @param enableUser true if the user should be enabled at creation
     * @since 2.5.0
     */
    public void setEnableUser(boolean enableUser)
    {
        this.xobject.setIntValue(FIELD_ENABLE_USER, enableUser ? 1 : 0);
    }
}
