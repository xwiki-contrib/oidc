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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.Session;
import org.xwiki.container.servlet.ServletSession;
import org.xwiki.contrib.oidc.provider.internal.OIDCManager;
import org.xwiki.contrib.oidc.provider.internal.endpoint.AuthorizationOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.TokenOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.endpoint.UserInfoOIDCEndpoint;
import org.xwiki.instance.InstanceIdManager;
import org.xwiki.properties.ConverterManager;

import com.nimbusds.oauth2.sdk.id.State;

/**
 * Various OpenId Connect authenticator configurations.
 * 
 * @version $Id$
 */
@Component(roles = OIDCClientConfiguration.class)
@Singleton
public class OIDCClientConfiguration
{
    public static final String PROP_PROVIDER = "oidc.provider";

    public static final String PROP_USER_NAMEFORMATER = "oidc.user.nameFormater";

    public static final String DEFAULT_USER_NAMEFORMATER = "${oidc.provider.host.clean}-${oidc.subject.clean}";

    public static final String PROPPREFIX_ENDPOINT = "oidc.endpoint.";

    public static final String PROP_ENDPOINT_AUTHORIZATION = PROPPREFIX_ENDPOINT + AuthorizationOIDCEndpoint.HINT;

    public static final String PROP_ENDPOINT_TOKEN = PROPPREFIX_ENDPOINT + TokenOIDCEndpoint.HINT;

    public static final String PROP_ENDPOINT_USERINFO = PROPPREFIX_ENDPOINT + UserInfoOIDCEndpoint.HINT;

    public static final String PROP_CLIENTID = "oidc.clientid";

    public static final String PROP_SKIPPED = "oidc.skipped";

    public static final String PROP_INITIAL_REQUEST = "xwiki.initialRequest";

    public static final String PROP_STATE = "oidc.state";

    @Inject
    private Logger logger;

    @Inject
    private InstanceIdManager instance;

    @Inject
    private OIDCManager manager;

    @Inject
    private Container container;

    @Inject
    private ConverterManager converter;

    @Inject
    // TODO: store configuration in custom objects
    private ConfigurationSource configuration;

    private HttpSession getHttpSession()
    {
        Session session = this.container.getSession();
        if (session instanceof ServletSession) {
            return ((ServletSession) session).getHttpSession();
        }

        return null;
    }

    private <T> T getSessionAttribute(String key)
    {
        HttpSession session = getHttpSession();
        if (session != null) {
            return (T) session.getAttribute(key);
        }

        return null;
    }

    private String getRequestParameter(String key)
    {
        Request request = this.container.getRequest();
        if (request != null) {
            return (String) request.getProperty(key);
        }

        return null;
    }

    public <T> T getProperty(String key, Class<T> valueClass)
    {
        // Get property from request
        String requestValue = getRequestParameter(key);
        if (requestValue != null) {
            return this.converter.convert(valueClass, requestValue);
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get property from configuration
        return this.configuration.getProperty(key, valueClass);
    }

    private <T> T getProperty(String key, T def)
    {
        // Get property from request
        String requestValue = getRequestParameter(key);
        if (requestValue != null) {
            return this.converter.convert(def.getClass(), requestValue);
        }

        // Get property from session
        T sessionValue = getSessionAttribute(key);
        if (sessionValue != null) {
            return sessionValue;
        }

        // Get property from configuration
        return this.configuration.getProperty(key, def);
    }

    public String getUserNameFormater()
    {
        String userFormatter = getProperty(DEFAULT_USER_NAMEFORMATER, String.class);
        if (userFormatter == null) {
            userFormatter = DEFAULT_USER_NAMEFORMATER;
        }

        return userFormatter;
    }

    public URL getProvider()
    {
        return getProperty(PROP_PROVIDER, URL.class);
    }

    private URI getEndPoint(String hint) throws URISyntaxException, MalformedURLException
    {
        URL endpoint = getProperty(PROPPREFIX_ENDPOINT + hint, URL.class);

        if (endpoint == null) {
            URL provider = getProvider();
            if (provider != null) {
                endpoint = this.manager.createEndPointURI(getProvider().toURI().toString(), hint).toURL();
            }
        }

        return endpoint == null ? null : endpoint.toURI();
    }

    public URI getAuthorizationOIDCEndpoint() throws URISyntaxException, MalformedURLException
    {
        return getEndPoint(AuthorizationOIDCEndpoint.HINT);
    }

    public URI getTokenOIDCEndpoint() throws URISyntaxException, MalformedURLException
    {
        return getEndPoint(TokenOIDCEndpoint.HINT);
    }

    public URI getUserInfoOIDCEndpoint() throws URISyntaxException, MalformedURLException
    {
        return getEndPoint(UserInfoOIDCEndpoint.HINT);
    }

    public String getClientID()
    {
        String clientId = getProperty(PROP_CLIENTID, String.class);

        // Fallback on instance id
        return clientId != null ? clientId : this.instance.getInstanceId().getInstanceId();
    }

    public State getSessionState()
    {
        return getSessionAttribute(PROP_STATE);
    }

    public boolean isSkipped()
    {
        return getProperty(PROP_SKIPPED, false);
    }
}
