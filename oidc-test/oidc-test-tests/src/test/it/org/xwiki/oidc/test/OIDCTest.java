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

import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.xwiki.contrib.oidc.auth.internal.endpoint.CallbackOIDCEndpoint;
import org.xwiki.contrib.oidc.provider.internal.store.BaseObjectOIDCClient;
import org.xwiki.contrib.oidc.provider.internal.store.OIDCProviderClientsInitializer;
import org.xwiki.contrib.oidc.test.po.OIDCAdministrationSectionPage;
import org.xwiki.contrib.oidc.test.po.OIDCApplicationsUserProfilePage;
import org.xwiki.contrib.oidc.test.po.OIDCClientProviderPage;
import org.xwiki.contrib.oidc.test.po.OIDCProviderConsentPage;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.test.integration.XWikiExecutor;
import org.xwiki.test.ui.AbstractTest;
import org.xwiki.test.ui.PersistentTestContext;
import org.xwiki.test.ui.TestUtils;
import org.xwiki.test.ui.po.LoginPage;
import org.xwiki.test.ui.po.ViewPage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

/**
 * Verify the document cache update based on distributed events.
 * 
 * @version $Id: f6ae6de6d59b97c88b228130b45cd26ce7b305ff $
 */
public class OIDCTest extends AbstractTest
{
    // We have to use a different domains for the client and the provider or it's going to mess with the session
    private static final String[] HOSTS = new String[] {"localhost:8080", "127.0.0.1:8081"};
    private static final String[] URL_PREFIXES = new String[] {"http://localhost", "http://127.0.0.1"};

    private static final LocalDocumentReference PROVIDER_USER_REFERENCE =
        new LocalDocumentReference("XWiki", "provideruser");

    private static final LocalDocumentReference CLIENT_USER_REFERENCE =
        new LocalDocumentReference("XWiki", "127001-provideruser");

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

    private void switchExecutor(int index)
    {
        getUtil().switchExecutor(index);
        // Force a different host depending on the instance
        TestUtils.setURLPrefix(URL_PREFIXES[index]);
        // Cache the initial CSRF token since that token needs to be passed to all forms (this is done automatically
        // in TestUtils), including the login form. Whenever a new user logs in we need to recache.
        // Note that this requires a running XWiki instance.
        getUtil().recacheSecretToken();
    }

    private void cleanupProvider() throws Exception
    {
        switchExecutor(1);
        getUtil().loginAsSuperAdmin();
        // Delete user if already exist
        getUtil().rest().delete(PROVIDER_USER_REFERENCE);
        // Empty clients
        getUtil().rest().delete(OIDCProviderClientsInitializer.REFERENCE);
        getUtil().rest().savePage(OIDCProviderClientsInitializer.REFERENCE);
        // Logout
        logout();
    }

    private void cleanupClient() throws Exception
    {
        switchExecutor(0);
        getUtil().loginAsSuperAdmin();
        // Delete user if already exist
        getUtil().rest().delete(CLIENT_USER_REFERENCE);
        // Reset client authentication configuration
        getUtil().setPropertyInXWikiPreferences("oidc.clientid", "String", "");
        getUtil().setPropertyInXWikiPreferences("oidc.secret", "String", "");

        // Logout
        logout();
    }

    private void gotToLogin(int index)
    {
        // BasePage#login() assume it ends up in the standard login page, so we cannot use it
        gotoHome(index);
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

    private void logout()
    {
        gotoHome().logout();
    }

    private String getHomeURL(int index)
    {
        return getURL(index, "/bin/view/Main/");
    }

    private ViewPage gotoHome()
    {
        return getUtil().gotoPage("Main", "");
    }

    private ViewPage gotoHome(int index)
    {
       switchExecutor(index);
       return gotoHome();
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
        getUtil().createUser("provideruser", "providerpassword", null);

        // Go to token management of provideruser
        getUtil().gotoPage(getURL(1, "/bin/view/XWiki/provideruser?category=userapplications"));
        // Make sure guest user is not allowed to access the user token management
        assertFalse(OIDCApplicationsUserProfilePage.isAllowed());

        /////////////////////////////////////////////////////////////
        // Dynamic client mode

        // Make sure the provider is configured in dynamic client mode
        switchExecutor(1);
        getUtil().loginAsSuperAdmin();
        OIDCAdministrationSectionPage administrationSectionPage = OIDCAdministrationSectionPage.gotoPage();
        administrationSectionPage.setDynamicMode();
        administrationSectionPage.clickSaveButton();
        logout();

        // Login on the client
        gotToLogin(0);

        // We are asked for the provider to use, set it
        OIDCClientProviderPage providerPage = new OIDCClientProviderPage();
        providerPage.setProvider(getURL(1, "/oidc"));
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

        // Log out on the client
        switchExecutor(0);
        logout();

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

        // Log out of the client
        switchExecutor(0);
        logout();

        /////////////////////////////////////////////////////////////
        // Static client mode (not registered)

        // Make sure the provider is configured in dynamic client mode
        switchExecutor(1);
        getUtil().loginAsSuperAdmin();
        administrationSectionPage = OIDCAdministrationSectionPage.gotoPage();
        administrationSectionPage.setStaticMode();
        administrationSectionPage = administrationSectionPage.clickSaveButton();
        administrationSectionPage.logout();

        // Login on the client
        gotToLogin(0);

        // Choose the provider
        providerPage = new OIDCClientProviderPage();
        providerPage.setProvider(getURL(1, "/oidc"));
        providerPage.clickAuthenticate();

        // It fail immediately since the client is not registered in static mode

        // Make sure we are not logged in
        gotoHome(0);
        assertNull(getCurrentUserReference());

        /////////////////////////////////////////////////////////////
        // Static client mode (registered)

        // Register the client on the provider side
        gotoHome(1);
        getUtil().loginAsSuperAdmin();
        String clientID = "clientid";
        String clientSecret = "clientsecret";
        getUtil().addObject(OIDCProviderClientsInitializer.REFERENCE, BaseObjectOIDCClient.REFERENCE_STRING, "id",
            "clientid", "secret", "clientsecret", "redirectURIs", getURL(0, "/oidc/" + CallbackOIDCEndpoint.HINT),
            "enabled", "1");
        logout();
        // Configure the authenticator with registered client metadata
        gotoHome(0);
        getUtil().loginAsSuperAdmin();
        getUtil().setPropertyInXWikiPreferences("oidc.clientid", "String", clientID);
        getUtil().setPropertyInXWikiPreferences("oidc.secret", "String", clientSecret);
        logout();

        // Login on the client
        gotToLogin(0);
        gotToLogin(0);

        // Choose the provider
        providerPage = new OIDCClientProviderPage();
        providerPage.setProvider(getURL(1, "/oidc"));
        providerPage.clickAuthenticate();

        // It gets redirected to the provider login page, login
        loginPage = new LoginPage();
        loginPage.loginAs("provideruser", "providerpassword");
        // A consent is asked (since the client id changed), accept
        consentPage = new OIDCProviderConsentPage();
        consentPage.clickAccept();

        // It gets redirected back to the client authenticated with the remote user
        assertEquals(getHomeURL(0), getUtil().getDriver().getCurrentUrl());

        // Make sure the we are authenticated and we get the expected id on client side
        assertEquals("xwiki:XWiki.127001-provideruser", getCurrentUserReference());

        /////////////////////////////////////////////////////////////
        // Token access

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
