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

import java.util.List;
import java.util.Properties;

import org.junit.runner.RunWith;
import org.xwiki.contrib.oidc.auth.OIDCAuthServiceImpl;
import org.xwiki.contrib.oidc.provider.OIDCBridgeAuth;
import org.xwiki.test.integration.XWikiExecutor;
import org.xwiki.test.ui.PageObjectSuite;

/**
 * Runs all functional tests found in the classpath and start/stop XWiki before/after the tests (only once).
 * 
 * @version $Id: d3e56ad3c752de51da619b17c75e9b54b8d0712a $
 */
@RunWith(PageObjectSuite.class)
@PageObjectSuite.Executors(2)
public class AllTests
{
    @PageObjectSuite.PreStart
    public void preStart(List<XWikiExecutor> executors) throws Exception
    {
        setupAuthenticator(executors.get(0));
        setupProvider(executors.get(1));
    }

    private void setupAuthenticator(XWikiExecutor executor) throws Exception
    {
        Properties properties = executor.loadXWikiCfg();
        properties.setProperty("xwiki.authentication.authclass", OIDCAuthServiceImpl.class.getCanonicalName());
        executor.saveXWikiCfg(properties);
    }

    private void setupProvider(XWikiExecutor executor) throws Exception
    {
        Properties properties = executor.loadXWikiCfg();
        properties.setProperty("xwiki.authentication.authclass", OIDCBridgeAuth.class.getCanonicalName());
        executor.saveXWikiCfg(properties);
    }
}
