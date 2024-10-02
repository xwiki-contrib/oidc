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

    private XWikiAuthService authService;

    private OIDCProviderAuthenticator oidcAuthenticator = Utils.getComponent(OIDCProviderAuthenticator.class);

    private OIDCProviderConfiguration configuration = Utils.getComponent(OIDCProviderConfiguration.class);

    /**
     * Initialize the wrapped authenticator.
     */
    public OIDCBridgeAuth()
    {
        String auth = this.configuration.getAuthenticator();

        createAuthService(auth);
    }

    private void createAuthService(String auth)
    {
        if (StringUtils.isNotEmpty(auth)) {
            LOGGER.debug("Using custom AuthClass [{}].", auth);

            try {
                // Get the current ClassLoader
                @SuppressWarnings("deprecation")
                ClassLoaderManager clManager = Utils.getComponent(ClassLoaderManager.class);
                ClassLoader classloader = null;
                if (clManager != null) {
                    classloader = clManager.getURLClassLoader("wiki:xwiki", false);
                }

                // Get the class
                if (classloader != null) {
                    this.authService = (XWikiAuthService) Class.forName(auth, true, classloader).newInstance();
                } else {
                    this.authService = (XWikiAuthService) Class.forName(auth).newInstance();
                }

                LOGGER.debug("Initialized AuthService using Reflection.");

                return;
            } catch (Exception e) {
                LOGGER.warn("Failed to initialize AuthService " + auth
                    + " using Reflection, trying default implementations using 'new'.", e);
            }
        }

        this.authService = new XWikiAuthServiceImpl();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Initialized AuthService [{}] using 'new'.", this.authService.getClass().getName());
        }
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

        return this.authService.checkAuth(context);
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        this.authService.showLogin(context);
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        return this.authService.checkAuth(username, password, rememberme, context);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        return this.authService.authenticate(username, password, context);
    }
}
