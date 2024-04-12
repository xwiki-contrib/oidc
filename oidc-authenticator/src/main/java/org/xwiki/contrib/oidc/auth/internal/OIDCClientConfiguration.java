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
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.SetUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.joda.time.LocalDateTime;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.Session;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.OIDCIdToken;
import org.xwiki.contrib.oidc.OIDCUserInfo;
import org.xwiki.contrib.oidc.auth.internal.endpoint.BackChannelLogoutOIDCEndpoint;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders;
import org.xwiki.contrib.oidc.auth.internal.session.ClientProviders.ClientProvider;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfigurationStore;
import org.xwiki.contrib.oidc.internal.OIDCConfiguration;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.endpoint.AuthorizationOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.LogoutOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.RegisterAddOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.TokenOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.UserInfoOIDCEndpoint;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.properties.ConverterManager;
import org.xwiki.query.QueryException;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.web.XWikiServletRequest;

/**
 * Various OpenID Connect authenticator configurations.
 * 
 * @version $Id$
 */
@Component(roles = OIDCClientConfiguration.class)
@Singleton
public class OIDCClientConfiguration extends OIDCConfiguration
{
    public class GroupMapping
    {
        private final Map<String, Set<String>> xwikiMapping;

        private final Map<String, Set<String>> providerMapping;

        public GroupMapping(int size)
        {
            this.xwikiMapping = new HashMap<>(size);
            this.providerMapping = new HashMap<>(size);
        }

        public Set<String> fromXWiki(String xwikiGroup)
        {
            return this.xwikiMapping.get(xwikiGroup);
        }

        public Set<String> fromProvider(String providerGroup)
        {
            return this.providerMapping.get(providerGroup);
        }

        public Map<String, Set<String>> getXWikiMapping()
        {
            return this.xwikiMapping;
        }

        public Map<String, Set<String>> getProviderMapping()
        {
            return this.providerMapping;
        }
    }

    public static final String SESSION = "oidc";

    @Deprecated(since = "2.4.0")
    private static final String PROP_XWIKIPROVIDER = "oidc.xwikiprovider";

    public static final String PROP_PROVIDER = "oidc.provider";

    public static final String PROP_USER_NAMEFORMATER = "oidc.user.nameFormater";

    public static final String DEFAULT_USER_NAMEFORMATER =
        "${oidc.issuer.host._clean}-${oidc.user.preferredUsername._clean}";

    /**
     * @since 1.11
     */
    public static final String PROP_USER_SUBJECTFORMATER = "oidc.user.subjectFormater";

    /**
     * @since 1.18
     */
    public static final String PROP_USER_MAPPING = "oidc.user.mapping";

    /**
     * @since 1.11
     */
    public static final String DEFAULT_USER_SUBJECTFORMATER = "${oidc.user.subject}";

    /**
     * @since 1.36.0
     */
    public static final String PROP_USER_OWNPROFILERIGHTS = "oidc.user.ownProfileRights";

    /**
     * @since 1.36.0
     */
    public static final String DEFAULT_USER_OWNPROFILERIGHTS = "edit";

    public static final String PROPPREFIX_ENDPOINT = "oidc.endpoint.";

    public static final String PROP_ENDPOINT_AUTHORIZATION = PROPPREFIX_ENDPOINT + AuthorizationOIDCEndpoint.HINT;

    public static final String PROP_ENDPOINT_TOKEN = PROPPREFIX_ENDPOINT + TokenOIDCEndpoint.HINT;

    public static final String PROP_ENDPOINT_USERINFO = PROPPREFIX_ENDPOINT + UserInfoOIDCEndpoint.HINT;

    /**
     * @since 1.21
     */
    public static final String PROP_ENDPOINT_LOGOUT = PROPPREFIX_ENDPOINT + "logout";

    public static final String PROP_CLIENTID = "oidc.clientid";

    /**
     * @since 2.4.0
     */
    public static final String PROP_PROVIDERMETADATA = "oidc.providermetadata";

    /**
     * @since 1.13
     */
    public static final String PROP_SECRET = "oidc.secret";

    public static final String PROP_SKIPPED = "oidc.skipped";

    /**
     * @since 1.13
     */
    public static final String PROP_ENDPOINT_TOKEN_AUTH_METHOD =
        PROPPREFIX_ENDPOINT + TokenOIDCEndpoint.HINT + ".auth_method";

    /**
     * @since 1.13
     */
    public static final String PROP_ENDPOINT_USERINFO_METHOD =
        PROPPREFIX_ENDPOINT + UserInfoOIDCEndpoint.HINT + ".method";

    /**
     * @since 1.22
     */
    public static final String PROP_ENDPOINT_USERINFO_HEADERS =
        PROPPREFIX_ENDPOINT + UserInfoOIDCEndpoint.HINT + ".headers";

    /**
     * @since 1.21
     */
    public static final String PROP_ENDPOINT_LOGOUT_METHOD = PROPPREFIX_ENDPOINT + LogoutOIDCEndpoint.HINT + ".method";

    /**
     * @since 2.4.0
     */
    public static final String PROP_ENDPOINT_RESGISTER_TOKEN =
        PROPPREFIX_ENDPOINT + RegisterAddOIDCEndpoint.HINT + ".token";

    /**
     * @since 1.12
     */
    public static final String PROP_USERINFOREFRESHRATE = "oidc.userinforefreshrate";

    /**
     * @since 1.16
     */
    public static final String PROP_SCOPE = "oidc.scope";
    
    /**
     * @since 2.6.0
     */
    public static final String PROP_CLAIMS = "oidc.claims";

    public static final String PROP_USERINFOCLAIMS = "oidc.userinfoclaims";

    public static final List<String> DEFAULT_USERINFOCLAIMS = Arrays.asList(OIDCUserInfo.CLAIM_XWIKI_ACCESSIBILITY,
        OIDCUserInfo.CLAIM_XWIKI_COMPANY, OIDCUserInfo.CLAIM_XWIKI_DISPLAYHIDDENDOCUMENTS,
        OIDCUserInfo.CLAIM_XWIKI_EDITOR, OIDCUserInfo.CLAIM_XWIKI_USERTYPE);

    public static final String PROP_IDTOKENCLAIMS = "oidc.idtokenclaims";

    public static final List<String> DEFAULT_IDTOKENCLAIMS = Arrays.asList(OIDCIdToken.CLAIM_XWIKI_INSTANCE_ID);

    /**
     * @since 1.10
     */
    public static final String PROP_GROUPS_MAPPING = "oidc.groups.mapping";

    /**
     * @since 1.10
     */
    public static final String PROP_GROUPS_ALLOWED = "oidc.groups.allowed";

    /**
     * @since 1.10
     */
    public static final String PROP_GROUPS_FORBIDDEN = "oidc.groups.forbidden";

    /**
     * @since 1.27
     */
    public static final String PROP_GROUPS_PREFIX = "oidc.groups.prefix";

    /**
     * @since 1.27
     */
    public static final String PROP_GROUPS_SEPARATOR = "oidc.groups.separator";

    public static final String PROP_INITIAL_REQUEST = "xwiki.initialRequest";

    public static final String PROP_STATE = "oidc.state";

    public static final String PROP_SESSION_ACCESSTOKEN = "oidc.accesstoken";

    public static final String PROP_SESSION_IDTOKEN = "oidc.idtoken";

    public static final String PROP_SESSION_USERINFO_EXPORATIONDATE = "oidc.session.userinfoexpirationdate";

    /**
     * The name of the logout mechanism property.
     * 
     * @since 1.31
     */
    public static final String PROP_LOGOUT_MECHANISM = "oidc.logoutMechanism";

    private static final String XWIKI_GROUP_PREFIX = "XWiki.";

    private static final Set<String> SAFE_PROPERTIES = SetUtils.hashSet(PROP_SKIPPED);

    /**
     * The name of the property in which the name of the OIDC configuration should be stored.
     * 
     * @since 1.30
     */
    public static final String CLIENT_CONFIGURATION_COOKIE_PROPERTY =
        OIDCConfiguration.PREFIX_PROP + "clientConfigurationCookie";

    /**
     * The default name of the cookie in which the OIDC client configuration is defined.
     * 
     * @since 1.30
     */
    public static final String DEFAULT_OIDC_CONFIGURATION_COOKIE = "oidcProvider";

    /**
     * The name of the property which stores the name of the default OIDC client configuration.
     * 
     * @since 1.30
     */
    public static final String DEFAULT_CLIENT_CONFIGURATION_PROPERTY =
        OIDCConfiguration.PREFIX_PROP + "defaultClientConfiguration";

    /**
     * The name of the property which defines if users should be enabled by default
     *
     * @since 2.5.0
     */
    public static final String PROP_ENABLE_USER = OIDCConfiguration.PREFIX_PROP + "enableUser";

    /**
     * Default client configuration to use when no configuration is defined.
     * 
     * @since 1.30
     */
    public static final String DEFAULT_CLIENT_CONFIGURATION = "default";

    @Inject
    private InstanceIdManager instance;

    @Inject
    private OIDCManager manager;

    @Inject
    private Container container;

    @Inject
    private ConverterManager converter;

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private OIDCClientConfigurationStore oidcClientConfigurationStore;

    @Inject
    private ClientProviders providers;

    @Inject
    @Named("xwikicfg")
    private ConfigurationSource xwikicfg;

    private Set<String> mandatoryXWikiGroups;

    /**
     * @since 2.4.0
     */
    public Map<String, Object> getOIDCSession(boolean create)
    {
        Session session = this.container.getSession();
        if (session instanceof ServletSession) {
            HttpSession httpSession = ((ServletSession) session).getHttpSession();

            this.logger.debug("Session: {}", httpSession.getId());

            Map<String, Object> oidcSession = (Map<String, Object>) httpSession.getAttribute(SESSION);
            if (oidcSession == null && create) {
                oidcSession = new ConcurrentHashMap<>();
                httpSession.setAttribute(SESSION, oidcSession);
            }

            return oidcSession;
        }

        return null;
    }

    public <T> T getSessionAttribute(String name)
    {
        Map<String, Object> session = getOIDCSession(false);
        if (session != null) {
            return (T) session.get(name);
        }

        return null;
    }

    public <T> T removeSessionAttribute(String name)
    {
        Map<String, Object> session = getOIDCSession(false);
        if (session != null) {
            try {
                return (T) session.get(name);
            } finally {
                session.remove(name);
            }
        }

        return null;
    }

    public void setSessionAttribute(String name, Object value)
    {
        Map<String, Object> session = getOIDCSession(true);
        if (session != null) {
            session.put(name, value);
        }
    }

    private String getRequestParameter(String key)
    {
        Request request = this.container.getRequest();
        if (request != null) {
            return (String) request.getProperty(key);
        }

        return null;
    }

    public Map<String, String> getMap(String key)
    {
        List<String> list = getProperty(key, List.class);

        Map<String, String> mapping;

        if (list != null && !list.isEmpty()) {
            mapping = new HashMap<>(list.size());

            for (String listItem : list) {
                int index = listItem.indexOf('=');

                if (index != -1) {
                    mapping.put(listItem.substring(0, index), listItem.substring(index + 1));
                }
            }
        } else {
            mapping = null;
        }

        return mapping;
    }

    @Override
    protected <T> T getProperty(String key, Class<T> valueClass)
    {
        if (SAFE_PROPERTIES.contains(key)) {
            // Get property from request
            String requestValue = getRequestParameter(key);
            if (requestValue != null) {
                return this.converter.convert(valueClass, requestValue);
            }
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get the property from the wiki configuration
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiClientConfiguration =
            getWikiClientConfiguration();
        if (wikiClientConfiguration != null) {
            T wikiValue = getWikiConfigurationAttribute(wikiClientConfiguration, key, valueClass);
            if (wikiValue != null) {
                return wikiValue;
            }
        }

        // Get property from configuration
        return this.configuration.getProperty(key, valueClass);
    }

    @Override
    protected <T> T getProperty(String key, T def)
    {
        if (SAFE_PROPERTIES.contains(key)) {
            // Get property from request
            String requestValue = getRequestParameter(key);
            if (requestValue != null) {
                return this.converter.convert(def.getClass(), requestValue);
            }
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get the property form the wiki configuration
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration wikiClientConfiguration =
            getWikiClientConfiguration();
        if (wikiClientConfiguration != null) {
            T wikiValue = getWikiConfigurationAttribute(wikiClientConfiguration, key, def.getClass());
            if (wikiValue != null) {
                return wikiValue;
            }
        }

        // Get property from configuration
        return this.configuration.getProperty(key, def);
    }

    /**
     * @since 1.18
     */
    public String getSubjectFormater()
    {
        String userFormatter = getProperty(PROP_USER_SUBJECTFORMATER, String.class);
        if (userFormatter == null) {
            userFormatter = DEFAULT_USER_SUBJECTFORMATER;
        }

        return userFormatter;
    }

    /**
     * @since 1.11
     */
    public String getXWikiUserNameFormater()
    {
        String userFormatter = getProperty(PROP_USER_NAMEFORMATER, String.class);
        if (userFormatter == null) {
            userFormatter = DEFAULT_USER_NAMEFORMATER;
        }

        return userFormatter;
    }

    /**
     * @since 1.18
     */
    public Map<String, String> getUserMapping()
    {
        return getMap(PROP_USER_MAPPING);
    }

    public String getProvider()
    {
        String provider = getProperty(PROP_PROVIDER, String.class);

        if (StringUtils.isEmpty(provider)) {
            // Try the old property
            provider = getProperty(PROP_XWIKIPROVIDER, String.class);
        }

        return provider;
    }

    /**
     * @since 2.4.0
     */
    public Issuer getIssuer()
    {
        String provider = getProvider();

        return provider != null ? Issuer.parse(provider) : null;
    }

    private Endpoint getEndPoint(String hint, Function<OIDCProviderMetadata, URI> providerSupplier)
        throws URISyntaxException, GeneralException, IOException
    {
        // TODO: use URI directly when upgrading to a version of XWiki providing a URI converter
        String uriString = getProperty(PROPPREFIX_ENDPOINT + hint, String.class);

        // If no direct endpoint check if the provided gave indicated one
        URI uri;
        if (uriString == null && providerSupplier != null) {
            ClientProvider clientProvider = getClientProvider();
            if (clientProvider != null) {
                uri = providerSupplier.apply(clientProvider.getMetadata());
            } else {
                uri = null;
            }
        } else {
            uri = new URI(uriString);
        }

        // If we still don't have any endpoint URI, try the request
        if (uri == null) {
            uriString = getRequestParameter(PROPPREFIX_ENDPOINT + hint);
            if (uriString == null) {
                String provider = getRequestParameter(PROP_PROVIDER);
                if (provider == null) {
                    return null;
                }

                uri = this.manager.createEndPointURI(provider, hint);
            } else {
                uri = new URI(uriString);
            }
        }

        // Find custom headers
        Map<String, List<String>> headers = new LinkedHashMap<>();

        List<String> entries = getProperty(PROPPREFIX_ENDPOINT + hint + ".headers", List.class);
        if (entries != null) {
            for (String entry : entries) {
                int index = entry.indexOf(':');

                if (index > 0 && index < entry.length() - 1) {
                    headers.computeIfAbsent(entry.substring(0, index), key -> new ArrayList<>())
                        .add(entry.substring(index + 1));
                }
            }
        }

        return new Endpoint(uri, headers);
    }

    public Endpoint getAuthorizationOIDCEndpoint() throws URISyntaxException, GeneralException, IOException
    {
        return getEndPoint(AuthorizationOIDCEndpoint.HINT, m -> m.getAuthorizationEndpointURI());
    }

    public Endpoint getTokenOIDCEndpoint() throws URISyntaxException, GeneralException, IOException
    {
        return getEndPoint(TokenOIDCEndpoint.HINT, m -> m.getTokenEndpointURI());
    }

    public Endpoint getUserInfoOIDCEndpoint() throws URISyntaxException, GeneralException, IOException
    {
        return getEndPoint(UserInfoOIDCEndpoint.HINT, m -> m.getUserInfoEndpointURI());
    }

    /**
     * @since 1.21
     */
    public Endpoint getLogoutOIDCEndpoint() throws URISyntaxException, GeneralException, IOException
    {
        return getEndPoint("logout", m -> m.getEndSessionEndpointURI());
    }

    public ClientID getClientID() throws GeneralException, IOException, URISyntaxException
    {
        return getClientID(getIssuer());
    }

    public ClientID getConfiguredClientID()
    {
        String clientIdString = getProperty(PROP_CLIENTID, String.class);

        return clientIdString != null ? new ClientID(clientIdString) : null;
    }

    public ClientID getClientID(Issuer issuer) throws GeneralException, IOException, URISyntaxException
    {
        // Try the configuration
        ClientID clientId = getConfiguredClientID();
        if (clientId != null) {
            return clientId;
        }

        // Ask the provider
        ClientProvider clientProvider = getClientProvider(issuer);
        if (clientProvider != null && clientProvider.getClientID() != null) {
            return clientProvider.getClientID();
        }

        // Fallback on instance id
        return new ClientID(this.instance.getInstanceId().getInstanceId());
    }

    public ClientProvider getClientProvider() throws GeneralException, IOException, URISyntaxException
    {
        return getClientProvider(getIssuer());
    }

    public ClientProvider getClientProvider(Issuer issuer) throws GeneralException, IOException, URISyntaxException
    {
        if (issuer == null) {
            return null;
        }

        ClientProvider clientProvider = this.providers.getClientProvider(issuer);

        if (clientProvider != null) {
            return clientProvider;
        }

        // Get provider metadata
        OIDCProviderMetadata providerMetadata = OIDCProviderMetadata.resolve(issuer);

        // If not client id is explicitly provided, try to register the client
        ClientID clientID = getConfiguredClientID();
        if (clientID == null) {
            URI registrationEndpoint = providerMetadata.getRegistrationEndpointURI();
            if (registrationEndpoint != null) {
                OIDCClientRegistrationRequest request = new OIDCClientRegistrationRequest(registrationEndpoint,
                    createClientMetadata(), getRegisterEndpointToken());

                HTTPRequest httpRequest = request.toHTTPRequest();
                HTTPResponse httpResponse = httpRequest.send();

                OIDCClientInformationResponse response = OIDCClientInformationResponse.parse(httpResponse);

                clientID = response.getOIDCClientInformation().getID();
            }
        }

        return this.providers.setClientProvider(issuer, providerMetadata, clientID);
    }

    public OIDCClientMetadata createClientMetadata() throws MalformedURLException, URISyntaxException
    {
        OIDCClientMetadata metadata = new OIDCClientMetadata();

        metadata.setApplicationType(ApplicationType.WEB);
        metadata.setBackChannelLogoutURI(this.manager.createEndPointURI(BackChannelLogoutOIDCEndpoint.HINT));
        metadata.setIDTokenJWSAlg(JWSAlgorithm.RS256);
        metadata.setRedirectionURI(this.manager.createEndPointURI(CallbackOIDCEndpoint.HINT));

        return metadata;
    }

    public OIDCClientInformation createClientInformation() throws URISyntaxException, GeneralException, IOException
    {
        return createClientInformation(getIssuer());
    }

    public OIDCClientInformation createClientInformation(Issuer issuer)
        throws URISyntaxException, GeneralException, IOException
    {
        return new OIDCClientInformation(getClientID(issuer), createClientMetadata());
    }

    /**
     * @since 1.13
     */
    public Secret getSecret()
    {
        String secret = getProperty(PROP_SECRET, String.class);
        if (StringUtils.isBlank(secret)) {
            return null;
        } else {
            return new Secret(secret);
        }
    }

    /**
     * @since 1.13
     */
    public ClientAuthenticationMethod getTokenEndPointAuthMethod()
    {
        String authMethod = getProperty(PROP_ENDPOINT_TOKEN_AUTH_METHOD, String.class);
        if ("client_secret_post".equalsIgnoreCase(authMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }
    }

    /**
     * @since 1.13
     */
    public HTTPRequest.Method getUserInfoEndPointMethod()
    {
        return getProperty(PROP_ENDPOINT_USERINFO_METHOD, HTTPRequest.Method.GET);
    }

    public String getSessionState()
    {
        return getSessionAttribute(PROP_STATE);
    }

    public void setSessionState(String state)
    {
        setSessionAttribute(PROP_STATE, state);
    }

    public String removeSessionState()
    {
        return removeSessionAttribute(PROP_STATE);
    }

    public boolean isSkipped()
    {
        return getProperty(PROP_SKIPPED, false);
    }

    /**
     * @since 1.2
     */
    public OIDCClaimsRequest getClaimsRequest()
    {
        // Parse the complete claims JSON if configured
        String claimsJson = getProperty(PROP_CLAIMS, String.class);
        OIDCClaimsRequest claimsRequest = null;
        if (claimsJson != null && claimsJson.trim().length() > 0) {
            try {
                claimsRequest = OIDCClaimsRequest.parse(claimsJson);
            } catch (ParseException e) {
                this.logger.warn("Parsing claims JSON [{}] failed with message: {}", claimsJson, ExceptionUtils.getRootCauseMessage(e));
            }
        }
        
        // Use idtokenclaims + userinfoclaims if json was not specified or if there was a parser error
        if (claimsRequest == null) {
            claimsRequest = new OIDCClaimsRequest();
            
            // ID Token claims
            List<String> idtokenclaims = getIDTokenClaims();
            if (idtokenclaims != null && !idtokenclaims.isEmpty()) {
                ClaimsSetRequest idtokenclaimsRequest = new ClaimsSetRequest();
                
                for (String claim : idtokenclaims) {
                    idtokenclaimsRequest = idtokenclaimsRequest.add(claim);
                }
                
                claimsRequest = claimsRequest.withIDTokenClaimsRequest(idtokenclaimsRequest);
            }
            
            // UserInfo claims
            List<String> userinfoclaims = getUserInfoClaims();
            if (userinfoclaims != null && !userinfoclaims.isEmpty()) {
                ClaimsSetRequest userinfoclaimsRequest = new ClaimsSetRequest();
                
                for (String claim : userinfoclaims) {
                    userinfoclaimsRequest = userinfoclaimsRequest.add(claim);
                }
                
                claimsRequest = claimsRequest.withUserInfoClaimsRequest(userinfoclaimsRequest);
            }
        }

        return claimsRequest;
    }

    private List<String> getListProperty(String key)
    {
        return getListProperty(key, null);
    }

    private List<String> getListProperty(String key, List<String> def)
    {
        List<String> claims = def != null ? getProperty(key, def) : getProperty(key, List.class);

        if (claims != null && claims.size() == 1 && claims.get(0).equals("")) {
            claims = Collections.emptyList();
        }

        return claims;
    }

    /**
     * @since 1.2
     */
    public List<String> getIDTokenClaims()
    {
        return getListProperty(PROP_IDTOKENCLAIMS, DEFAULT_IDTOKENCLAIMS);
    }

    /**
     * @since 1.2
     */
    public List<String> getUserInfoClaims()
    {
        return getListProperty(PROP_USERINFOCLAIMS, DEFAULT_USERINFOCLAIMS);
    }

    /**
     * @since 1.12
     */
    public int getUserInfoRefreshRate()
    {
        return getProperty(PROP_USERINFOREFRESHRATE, 600000);
    }

    /**
     * @since 1.2
     */
    public Scope getScope()
    {
        List<String> scopeValues = getProperty(PROP_SCOPE, List.class);

        if (CollectionUtils.isEmpty(scopeValues)) {
            return new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.PROFILE, OIDCScopeValue.EMAIL,
                OIDCScopeValue.ADDRESS, OIDCScopeValue.PHONE);
        }

        return new Scope(scopeValues.toArray(new String[0]));
    }

    /**
     * @since 1.10
     */
    public GroupMapping getGroupMapping()
    {
        List<String> groupsMapping = getProperty(PROP_GROUPS_MAPPING, List.class);

        GroupMapping groups;

        if (groupsMapping != null && !groupsMapping.isEmpty()) {
            groups = new GroupMapping(groupsMapping.size());

            for (String groupMapping : groupsMapping) {
                int index = groupMapping.indexOf('=');

                if (index != -1) {
                    String xwikiGroup = toXWikiGroup(groupMapping.substring(0, index));
                    String providerGroup = groupMapping.substring(index + 1);

                    // Add to XWiki mapping
                    Set<String> providerGroups = groups.xwikiMapping.computeIfAbsent(xwikiGroup, k -> new HashSet<>());
                    providerGroups.add(providerGroup);

                    // Add to provider mapping
                    Set<String> xwikiGroups =
                        groups.providerMapping.computeIfAbsent(providerGroup, k -> new HashSet<>());
                    xwikiGroups.add(xwikiGroup);
                }
            }
        } else {
            groups = null;
        }

        return groups;
    }

    /**
     * @since 1.10
     */
    public String toXWikiGroup(String group)
    {
        return group.startsWith(XWIKI_GROUP_PREFIX) ? group : XWIKI_GROUP_PREFIX + group;
    }

    /**
     * @since 1.10
     */
    public List<String> getAllowedGroups()
    {
        List<String> groups = getListProperty(PROP_GROUPS_ALLOWED);

        return groups != null && !groups.isEmpty() ? groups : null;
    }

    private boolean isAllGroupImplicit()
    {
        return "1".equals(this.xwikicfg.getProperty("xwiki.authentication.group.allgroupimplicit"));
    }

    /**
     * @since 2.4.0
     */
    public Set<String> getInitialXWikiGroups()
    {
        if (this.mandatoryXWikiGroups == null) {
            String groupsPreference = isAllGroupImplicit() ? this.xwikicfg.getProperty("xwiki.users.initialGroups")
                : this.xwikicfg.getProperty("xwiki.users.initialGroups", "XWiki.XWikiAllGroup");

            if (groupsPreference != null) {
                String[] groups = groupsPreference.split(",");

                this.mandatoryXWikiGroups = new HashSet<>(Arrays.asList(groups));
            } else {
                this.mandatoryXWikiGroups = Collections.emptySet();
            }
        }

        return this.mandatoryXWikiGroups;
    }

    /**
     * @since 1.10
     */
    public List<String> getForbiddenGroups()
    {
        List<String> groups = getListProperty(PROP_GROUPS_FORBIDDEN);

        return groups != null && !groups.isEmpty() ? groups : null;
    }

    /**
     * @since 1.27
     */
    public String getGroupPrefix()
    {
        String groupPrefix = getProperty(PROP_GROUPS_PREFIX, String.class);
        return groupPrefix != null && !groupPrefix.isEmpty() ? groupPrefix : null;
    }

    /**
     * @since 1.27
     */
    public String getGroupSeparator()
    {
        return getProperty(PROP_GROUPS_SEPARATOR, String.class);
    }

    /**
     * @return the right to give to the user on its own profile
     * @since 1.36.0
     */
    public String getUserOwnProfileRights()
    {
        return getProperty(PROP_USER_OWNPROFILERIGHTS, DEFAULT_USER_OWNPROFILERIGHTS);
    }

    /**
     * @return the token to use to access the register API
     * @since 2.4.0
     */
    public BearerAccessToken getRegisterEndpointToken()
    {
        String property = getProperty(PROP_ENDPOINT_RESGISTER_TOKEN, String.class);

        if (property == null) {
            return null;
        }

        return new BearerAccessToken(property);
    }

    // Session only

    /**
     * @since 1.2
     */
    public Date removeUserInfoExpirationDate()
    {
        return removeSessionAttribute(PROP_SESSION_USERINFO_EXPORATIONDATE);
    }

    /**
     * @since 1.2
     */
    public void setUserInfoExpirationDate(Date date)
    {
        setSessionAttribute(PROP_SESSION_USERINFO_EXPORATIONDATE, date);
    }

    /**
     * @since 1.2
     */
    public void resetUserInfoExpirationDate()
    {
        LocalDateTime expiration = LocalDateTime.now().plusMillis(getUserInfoRefreshRate());

        setUserInfoExpirationDate(expiration.toDate());
    }

    /**
     * @since 1.2
     */
    public BearerAccessToken getAccessToken()
    {
        String accessTokenValue = getSessionAttribute(PROP_SESSION_ACCESSTOKEN);

        return accessTokenValue != null ? new BearerAccessToken(accessTokenValue) : null;
    }

    /**
     * @since 1.2
     */
    public void setAccessToken(BearerAccessToken accessToken)
    {
        // Don't store the BearerAccessToken object directly as it could cause classloader problems when an extension is
        // upgraded
        setSessionAttribute(PROP_SESSION_ACCESSTOKEN, accessToken.getValue());
    }

    /**
     * @since 1.2
     */
    public IDTokenClaimsSet getIdToken()
    {
        String idTokenValue = getSessionAttribute(PROP_SESSION_IDTOKEN);

        try {
            return idTokenValue != null ? IDTokenClaimsSet.parse(idTokenValue) : null;
        } catch (ParseException e) {
            // Should never happen since the value was serialized from a IDTokenClaimsSet
            this.logger.error("Failed to parse the id token from the session with value [{}]", idTokenValue, e);

            // Return null in that case
            return null;
        }
    }

    /**
     * @since 1.2
     */
    public void setIdToken(IDTokenClaimsSet idToken)
    {
        // Don't store the IDTokenClaimsSet object directly as it could cause classloader problem when an extension is
        // upgraded
        setSessionAttribute(PROP_SESSION_IDTOKEN, idToken.toJSONString());
    }

    /**
     * @since 1.2
     */
    public URI getSuccessRedirectURI()
    {
        URI uri = getSessionAttribute(PROP_INITIAL_REQUEST);
        if (uri == null) {
            // TODO: return wiki hope page
        }

        return uri;
    }

    /**
     * @since 1.2
     */
    public void setSuccessRedirectURI(URI uri)
    {
        setSessionAttribute(PROP_INITIAL_REQUEST, uri);
    }

    /**
     * @return true if groups should be synchronized (in which case if the provider does not answer to the group claim
     *         it means the user does not belong to any group)
     * @since 1.14
     */
    public boolean isGroupSync()
    {
        String groupClaim = getGroupClaim();

        return getUserInfoClaims().contains(groupClaim);
    }

    /**
     * @return true if the user profile should be enabled on first login
     * @since 2.5.0
     */
    public boolean getEnableUser()
    {
        return getProperty(PROP_ENABLE_USER, true);
    }

    /**
     * @return the OIDC provider specified by the client for the authentication.
     */
    private String getOIDCProviderName()
    {
        String cookieName =
            configuration.getProperty(CLIENT_CONFIGURATION_COOKIE_PROPERTY, DEFAULT_OIDC_CONFIGURATION_COOKIE);

        String fallbackProviderName =
            configuration.getProperty(DEFAULT_CLIENT_CONFIGURATION_PROPERTY, DEFAULT_CLIENT_CONFIGURATION);

        // Check if a cookie exists, indicating which configuration to use
        XWikiContext context = contextProvider.get();
        if (context.getRequest() instanceof XWikiServletRequest) {
            XWikiServletRequest request = (XWikiServletRequest) context.getRequest();

            Cookie cookie = request.getCookie(cookieName);
            if (cookie != null) {
                // We need to save the chosen provider in the session, so that it's easier to get it when we don't
                // have access to the request.
                setSessionAttribute(DEFAULT_CLIENT_CONFIGURATION_PROPERTY, cookie.getValue());

                return cookie.getValue();
            }
        }

        // Check if the session has a key indicating which configuration to use
        String sessionProviderName = getSessionAttribute(DEFAULT_CLIENT_CONFIGURATION_PROPERTY);
        if (sessionProviderName != null) {
            return sessionProviderName;
        }

        return fallbackProviderName;
    }

    private org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration getWikiClientConfiguration()
    {
        String configName = getOIDCProviderName();

        this.logger.debug("Wiki configuration name is [{}]", configName);

        try {
            return oidcClientConfigurationStore.getOIDCClientConfiguration(configName);
        } catch (XWikiException | QueryException e) {
            this.logger.error("Failed to load the wiki OIDC client configuration with name [{}]", configName, e);
        }

        return null;
    }

    /**
     * Bridge to allow the conversion to the wiki client configuration.
     *
     * @param clientConfiguration the client configuration to use
     * @param key the key to look for
     * @param returnType the return type
     * @return the configuration. Null if the configuration key is invalid
     */
    private <T> T getWikiConfigurationAttribute(
        org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration clientConfiguration, String key, Type returnType)
    {
        Object returnValue = null;
        switch (key) {
            case PROP_GROUPS_CLAIM:
                returnValue = clientConfiguration.getGroupClaim();
                break;
            case PROP_GROUPS_MAPPING:
                returnValue = clientConfiguration.getGroupMapping();
                break;
            case PROP_GROUPS_ALLOWED:
                returnValue = clientConfiguration.getAllowedGroups();
                break;
            case PROP_GROUPS_FORBIDDEN:
                returnValue = clientConfiguration.getForbiddenGroups();
                break;
            case PROP_USER_SUBJECTFORMATER:
                returnValue = clientConfiguration.getUserSubjectFormatter();
                break;
            case PROP_USER_NAMEFORMATER:
                returnValue = clientConfiguration.getUserNameFormatter();
                break;
            case PROP_USER_MAPPING:
                returnValue = clientConfiguration.getUserMapping();
                break;
            case PROP_XWIKIPROVIDER:
                returnValue = clientConfiguration.getXWikiProvider();
                break;
            case PROP_ENDPOINT_AUTHORIZATION:
                returnValue = clientConfiguration.getAuthorizationEndpoint();
                break;
            case PROP_ENDPOINT_TOKEN:
                returnValue = clientConfiguration.getTokenEndpoint();
                break;
            case PROP_ENDPOINT_USERINFO:
                returnValue = clientConfiguration.getUserInfoEndpoint();
                break;
            case PROP_ENDPOINT_LOGOUT:
                returnValue = clientConfiguration.getLogoutEndpoint();
                break;
            case PROP_CLIENTID:
                returnValue = clientConfiguration.getClientId();
                break;
            case PROP_SECRET:
                returnValue = clientConfiguration.getClientSecret();
                break;
            case PROP_ENDPOINT_TOKEN_AUTH_METHOD:
                returnValue = clientConfiguration.getTokenEndpointMethod();
                break;
            case PROP_ENDPOINT_USERINFO_METHOD:
                returnValue = clientConfiguration.getUserInfoEndpointMethod();
                break;
            case PROP_ENDPOINT_USERINFO_HEADERS:
                returnValue = clientConfiguration.getUserInfoEndpointHeaders();
                break;
            case PROP_ENDPOINT_LOGOUT_METHOD:
                returnValue = clientConfiguration.getLogoutEndpointMethod();
                break;
            case PROP_ENDPOINT_RESGISTER_TOKEN:
                returnValue = clientConfiguration.getRegisterEndpointToken();
                break;
            case PROP_SKIPPED:
                returnValue = clientConfiguration.isSkipped();
                break;
            case PROP_SCOPE:
                returnValue = clientConfiguration.getScope();
                break;
            case PROP_IDTOKENCLAIMS:
                returnValue = Arrays.asList(clientConfiguration.getIdTokenClaims().toArray());
                break;
            case PROP_USERINFOCLAIMS:
                returnValue = Arrays.asList(clientConfiguration.getUserInfoClaims().toArray());
                break;
            case PROP_USERINFOREFRESHRATE:
                returnValue = clientConfiguration.getUserInfoRefreshRate();
                break;
            case PROP_LOGOUT_MECHANISM:
                returnValue = clientConfiguration.getLogoutMechanism();
                break;
            case PROP_ENABLE_USER:
                returnValue = clientConfiguration.getEnableUser();
                break;
        }

        this.logger.debug("The value of configuration property [{}] is [{}]", key, returnValue);

        if (returnValue != null && (!(returnValue instanceof String) || StringUtils.isNotBlank((String) returnValue))) {
            T convertedValue = this.converter.convert(returnType, returnValue);

            this.logger.debug("  Converted to [{}]", returnValue);

            return convertedValue;
        }

        return null;
    }
}
