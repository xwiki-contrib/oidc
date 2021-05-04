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
package org.xwiki.oidc.test;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xwiki.contrib.oidc.test.po.OIDCClientProviderPage;
import org.xwiki.contrib.oidc.test.po.OIDCProviderConsentPage;
import org.xwiki.test.integration.XWikiExecutor;
import org.xwiki.test.ui.AbstractTest;
import org.xwiki.test.ui.PersistentTestContext;
import org.xwiki.test.ui.po.LoginPage;
import org.xwiki.test.ui.po.ViewPage;

/**
 * Verify the document cache update based on distributed events.
 * 
 * @version $Id: f6ae6de6d59b97c88b228130b45cd26ce7b305ff $
 */
public class OIDCTest extends AbstractTest
{
    @BeforeClass
    public static void init() throws Exception
    {
        // This will not be null if we are in the middle of allTests
        if (context == null) {
            PersistentTestContext persistentTestContext =
                new PersistentTestContext(Arrays.asList(new XWikiExecutor(0), new XWikiExecutor(1)));
            initializeSystem(persistentTestContext);

            // Start XWiki
            persistentTestContext.start();

            // Cache the initial CSRF token since that token needs to be passed to all forms (this is done automatically
            // in TestUtils), including the login form. Whenever a new user logs in we need to recache.
            // Note that this requires a running XWiki instance.
            getUtil().recacheSecretToken();
        }
    }

    private void logout()
    {
        getUtil().gotoPage(getUtil().getURLToLogout());
    }

    private void gotToLogin()
    {
        getUtil().gotoPage(
            getUtil().getBaseBinURL() + "login/XWiki/XWikiLogin?xredirect=%2Fxwiki%2Fbin%2Fview%2FMain%2FWebHome");
    }

    private void cleanupProvider() throws Exception
    {
        getUtil().switchExecutor(1);
        // Delete user if already exist
        getUtil().rest().deletePage("XWiki", "provideruser");
        // Logout
        logout();
    }

    private void cleanupClient() throws Exception
    {
        getUtil().switchExecutor(0);
        // Delete user if already exist
        getUtil().rest().deletePage("XWiki", "127001-provideruser");
        // Logout
        logout();
    }

    @Test
    public void authenticate() throws Exception
    {
        cleanupClient();
        cleanupProvider();

        // Create a user on the provider
        getUtil().switchExecutor(1);
        getUtil().gotoPage("Main", "WebHome", "view");
        getUtil().recacheSecretToken();
        getUtil().createUser("provideruser", "providerpassword", null);

        // Go to client home page
        getUtil().switchExecutor(0);
        getUtil().gotoPage("Main", "WebHome", "view");

        // Login
        gotToLogin();
        // Go to client provider page
        OIDCClientProviderPage providerPage = new OIDCClientProviderPage();

        // Set other XWiki instance as provider
        providerPage.setProvider("http://127.0.0.1:8081/xwiki/oidc");

        // Start authentication
        providerPage.clickAuthenticate();
        // It gets redirected to the other wiki instance login page
        getUtil().switchExecutor(1);
        LoginPage loginPage = new LoginPage();

        // Login on the provider
        loginPage.loginAs("provideruser", "providerpassword");
        // A consent is asked
        OIDCProviderConsentPage consentPage = new OIDCProviderConsentPage();

        // Accept
        consentPage.clickAccept();
        // It gets redirected back to the client authenticated with the remote user
        getUtil().switchExecutor(0);
        ViewPage view = new ViewPage();

        // Make sure the we are authenticated and we get the expected id on client side
        Assert.assertEquals("127001-provideruser", view.getCurrentUser());

        // Logout from client
        logout();

        // Login again
        gotToLogin();
        // Go to client provider page
        providerPage = new OIDCClientProviderPage();

        // Set other XWiki instance as provider
        providerPage.setProvider("http://127.0.0.1:8081/xwiki/oidc");

        // Start authentication
        providerPage.clickAuthenticate();
        // The browser goes to the provider and immediately come back authenticated
        view = new ViewPage();

        // Make sure the we are authenticated and we get the expected id on client side
        Assert.assertEquals("127001-provideruser", view.getCurrentUser());
    }
}
