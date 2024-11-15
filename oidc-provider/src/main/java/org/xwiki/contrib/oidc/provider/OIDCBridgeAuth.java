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
package org.xwiki.contrib.oidc.provider;

import java.security.Principal;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.classloader.ClassLoaderManager;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderAuthenticator;
import org.xwiki.contrib.oidc.provider.internal.OIDCProviderConfiguration;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;

/**
 * Authenticate user trough an OpenID Connect provider.
 * 
 * @version $Id$
 * @since 1.15
 */
public class OIDCBridgeAuth implements XWikiAuthService
{
    private static final Logger LOGGER = LoggerFactory.getLogger(OIDCBridgeAuth.class);

    @SuppressWarnings("java:S3077")
    private volatile XWikiAuthService authService;

    private OIDCProviderAuthenticator oidcAuthenticator = Utils.getComponent(OIDCProviderAuthenticator.class);

    private OIDCProviderConfiguration configuration = Utils.getComponent(OIDCProviderConfiguration.class);

    /**
     * @return the configured "real" authenticator to fallback to when there is no token
     * @throws XWikiException when failing to get the authenticator
     */
    private XWikiAuthService getAuthService() throws XWikiException
    {
        if (this.authService == null) {
            synchronized (this) {
                if (this.authService == null) {
                    try {
                        this.authService = loadAuthService();
                    } catch (Exception e) {
                        throw new XWikiException("Failed to create the configured authenticator", e);
                    }
                }
            }
        }

        return this.authService;
    }

    private XWikiAuthService loadAuthService()
        throws InstantiationException, IllegalAccessException, ClassNotFoundException
    {
        String auth = this.configuration.getAuthenticator();

        if (StringUtils.isNotEmpty(auth)) {
            LOGGER.debug("Using custom AuthClass [{}].", auth);

            // Get the current ClassLoader
            @SuppressWarnings("deprecation")
            ClassLoaderManager clManager = Utils.getComponent(ClassLoaderManager.class);
            ClassLoader classloader = null;
            if (clManager != null) {
                classloader = clManager.getURLClassLoader("wiki:xwiki", false);
            }

            Class<?> serviceClass;
            // Get the class
            if (classloader != null) {
                serviceClass = Class.forName(auth, true, classloader);
            } else {
                serviceClass = Class.forName(auth);
            }

            return (XWikiAuthService) serviceClass.newInstance();
        }

        LOGGER.debug("Not custom auth class indicated, use the standard one");

        return new XWikiAuthServiceImpl();
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        String authorization = context.getRequest().getHeader("Authorization");

        try {
            XWikiUser user = this.oidcAuthenticator.checkAuth(authorization);

            if (user != null) {
                return user;
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to get OIDC user from HTTP authorization [" + authorization + "]", e);
        }

        return getAuthService().checkAuth(context);
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        getAuthService().showLogin(context);
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        return getAuthService().checkAuth(username, password, rememberme, context);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        return getAuthService().authenticate(username, password, context);
    }
}
