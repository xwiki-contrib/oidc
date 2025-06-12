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

import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;

import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.xwiki.contrib.oidc.test.po.OIDCApplicationsUserProfilePage;
import org.xwiki.contrib.oidc.test.po.OIDCClientProviderPage;
import org.xwiki.contrib.oidc.test.po.OIDCProviderConsentPage;
import org.xwiki.test.integration.XWikiExecutor;
import org.xwiki.test.ui.AbstractTest;
import org.xwiki.test.ui.PersistentTestContext;
import org.xwiki.test.ui.TestUtils;
import org.xwiki.test.ui.po.LoginPage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Verify the document cache update based on distributed events.
 * 
 * @version $Id: f6ae6de6d59b97c88b228130b45cd26ce7b305ff $
 */
public class OIDCTest extends AbstractTest
{
    // We have to use a different domains for the client and the provider or it's going to mess with the session
    private static final String[] HOSTS = new String[] {"localhost:8080", "127.0.0.1:8081"};

    @BeforeClass
    public static void init() throws Exception
    {
        // This will not be null if we are in the middle of allTests
        if (context == null) {
            PersistentTestContext persistentTestContext =
                new PersistentTestContext(Arrays.asList(new XWikiExecutor(0)/* , new XWikiExecutor(1) */));
            initializeSystem(persistentTestContext);

            // Start XWiki
            persistentTestContext.start();

            // Cache the initial CSRF token since that token needs to be passed to all forms (this is done automatically
            // in TestUtils), including the login form. Whenever a new user logs in we need to recache.
            // Note that this requires a running XWiki instance.
            getUtil().recacheSecretToken();
        }
    }

    private void cleanupProvider() throws Exception
    {
        getUtil().switchExecutor(1);
        // Delete user if already exist
        getUtil().rest().deletePage("XWiki", "provideruser");
        // Logout
        logout(1);
    }

    private void cleanupClient() throws Exception
    {
        getUtil().switchExecutor(0);
        // Delete user if already exist
        getUtil().rest().deletePage("XWiki", "127001-provideruser");
        // Logout
        logout(0);
    }

    private void gotToLogin(int index)
    {
        getUtil().switchExecutor(index);
        getUtil()
            .gotoPage(getUtil().getBaseBinURL() + "login/XWiki/XWikiLogin?xredirect=%2Fxwiki%2Fbin%2Fview%2FMain%2F");
    }

    private String getBaseURL(int index)
    {
        return "http://" + HOSTS[index] + "/xwiki";
    }

    private String getURL(int index, String path)
    {
        return getBaseURL(index) + path;
    }

    private void logout(int index)
    {
        getUtil().switchExecutor(index);
        getUtil().gotoPage(getURL(index, "/bin/logout/XWiki/XWikiLogout?xredirect=%2Fxwiki%2Fbin%2Fview%2FMain%2F"));
    }

    private void login(int index, UsernamePasswordCredentials credentials)
    {
        gotToLogin(index);
        LoginPage loginPage = new LoginPage();
        loginPage.loginAs(credentials.getUserName(), credentials.getPassword());
    }

    private String getHomeURL(int index)
    {
        return getURL(index, "/bin/view/Main/");
    }

    private void gotoHome(int index)
    {
        getUtil().switchExecutor(index);
        getUtil().gotoPage(getHomeURL(index));
    }

    private String getCurrentUserReference()
    {
        return getUtil().getDriver().findElementWithoutWaiting(By.tagName("html"))
            .getAttribute("data-xwiki-user-reference");
    }

    @Test
    public void authenticate() throws Exception
    {
        cleanupClient();
        cleanupProvider();

        // Create a user on the provider
        gotoHome(1);
        getUtil().recacheSecretToken();
        getUtil().createUser("provideruser", "providerpassword", null);

        // Go to token management of provideruser
        getUtil().gotoPage(getURL(1, "/bin/view/XWiki/provideruser?category=userapplications"));
        // Make sure guest user is not allowed to access the user token management
        assertFalse(OIDCApplicationsUserProfilePage.isAllowed());

        // Login on the client
        gotToLogin(0);

        // We are asked for the provider to use, set it
        OIDCClientProviderPage providerPage = new OIDCClientProviderPage();
        providerPage.setProvider(getURL(1, "/oidc"));

        // Start authentication
        providerPage.clickAuthenticate();

        // It gets redirected to the provider login page, login
        LoginPage loginPage = new LoginPage();
        loginPage.loginAs("provideruser", "providerpassword");
        // A consent is asked, accept
        OIDCProviderConsentPage consentPage = new OIDCProviderConsentPage();
        consentPage.clickAccept();

        // It gets redirected back to the client authenticated with the remote user
        assertEquals(getHomeURL(0), getUtil().getDriver().getCurrentUrl());

        // Make sure the we are authenticated and we get the expected id on client side
        assertEquals("xwiki:XWiki.127001-provideruser", getCurrentUserReference());

        // Log out of the client
        logout(0);

        // We are logged out of the provider and come back on the client
        assertEquals(getHomeURL(0), getUtil().getDriver().getCurrentUrl());

        // Make sure we are logged out of the client
        assertNull(getCurrentUserReference());

        // Make sure we are logged out of the provider too
        gotoHome(1);
        assertNull(getCurrentUserReference());

        // Login again
        gotToLogin(0);

        // We are asked for the provider to use, set it
        providerPage = new OIDCClientProviderPage();
        providerPage.setProvider(getURL(1, "/oidc"));

        // Start authentication
        providerPage.clickAuthenticate();

        // It gets redirected to the provider login page, login
        loginPage = new LoginPage();
        loginPage.loginAs("provideruser", "providerpassword");
        // No consent is needed this time

        // It gets redirected back to the client authenticated with the remote user
        assertEquals(getHomeURL(0), getUtil().getDriver().getCurrentUrl());

        // Make sure the we are authenticated and we get the expected id on client side
        assertEquals("xwiki:XWiki.127001-provideruser", getCurrentUserReference());

        // Make sure the user is logged in the provider
        gotoHome(1);
        assertEquals("xwiki:XWiki.provideruser", getCurrentUserReference());

        // Create a token on the provider
        getUtil().gotoPage(getURL(1, "/bin/view/XWiki/provideruser?category=userapplications"));
        OIDCApplicationsUserProfilePage applications = new OIDCApplicationsUserProfilePage("provideruser");

        applications.setApplicationName("My Application");
        applications = applications.clickCreate();

        String token = applications.getToken();

        URL url = new URL(getURL(1, "/rest/"));
        URLConnection connection = url.openConnection();
        connection.setRequestProperty("Authorization", "Bearer " + token);
        connection.connect();

        assertEquals("xwiki:XWiki.provideruser", connection.getHeaderField("XWiki-User"));

        // TODO: Add support on provider side to automatically catch standard logout and send a backchannel logout to
        // all registered clients
        // Log out of the provider
        // logout(1);
        //
        // Make sure we are logged out of the provider
        // assertNull(getCurrentUserReference());
        //
        // Make sure we are also logged out of the client
        // gotoHome(0);
        // assertNull(getCurrentUserReference());
    }
}
