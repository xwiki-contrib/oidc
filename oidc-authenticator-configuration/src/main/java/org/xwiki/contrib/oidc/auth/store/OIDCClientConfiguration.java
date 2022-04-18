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
    public static final LocalDocumentReference CLASS_REFERENCE = new LocalDocumentReference(Arrays.asList(
        XWiki.SYSTEM_SPACE, "OIDC"), "ClientConfigurationClass");

    /**
     * Name of the property containing the configuration.
     */
    public static final String FIELD_CONFIGURATION_NAME = "configurationName";

    /**
     * Name of the property containing the groups claim.
     */
    public static final String FIELD_CLAIM_GROUP = "groupsClaim";

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
     * Name of the property containing the user info refresh rate.
     */
    public static final String FIELD_USER_INFO_REFRESH_RATE = "userInfoRefreshRate";

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
        return this.xobject.getListValue(FIELD_USER_MAPPING);
    }

    /**
     * @param userMapping the user mapping
     */
    public void setUserMapping(List<String> userMapping)
    {
        this.xobject.setStringListValue(FIELD_USER_MAPPING, userMapping);
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
        return this.xobject.getListValue(FIELD_ENDPOINT_USERINFO_HEADERS);
    }

    /**
     * @param userInfoEndpointHeaders the user info endpoint headers
     */
    public void setUserInfoEndpointHeaders(List<String> userInfoEndpointHeaders)
    {
        this.xobject.setStringListValue(FIELD_ENDPOINT_USERINFO_HEADERS, userInfoEndpointHeaders);
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
        return this.xobject.getListValue(FIELD_SCOPE);
    }

    /**
     * @param scope the scope
     */
    public void setScope(List<String> scope)
    {
        this.xobject.setStringListValue(FIELD_SCOPE, scope);
    }

    /**
     * @return the id token claims
     */
    public List<String> getIdTokenClaims()
    {
        return this.xobject.getListValue(FIELD_CLAIMS_ID_TOKEN);
    }

    /**
     * @param idTokenClaims the id token claims
     */
    public void setIdTokenClaims(List<String> idTokenClaims)
    {
        this.xobject.setStringListValue(FIELD_CLAIMS_ID_TOKEN, idTokenClaims);
    }

    /**
     * @return the user info claims
     */
    public List<String> getUserInfoClaims()
    {
        return this.xobject.getListValue(FIELD_CLAIMS_USER_INFO);
    }

    /**
     * @param userInfoClaims the user info claims
     */
    public void setUserInfoClaims(List<String> userInfoClaims)
    {
        this.xobject.setStringListValue(FIELD_CLAIMS_USER_INFO, userInfoClaims);
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
}
