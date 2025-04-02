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
package org.xwiki.contrib.oidc.auth.internal.store;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.cache.Cache;
import org.xwiki.cache.CacheException;
import org.xwiki.cache.CacheManager;
import org.xwiki.cache.config.LRUCacheConfiguration;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLifecycleException;
import org.xwiki.component.phase.Disposable;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.contrib.oidc.auth.store.OIDCClientConfiguration;

/**
 * @version $Id$
 * @since 2.16.2
 */
@Component(roles = OIDCClientConfigurationCache.class)
@Singleton
public class OIDCClientConfigurationCache implements Initializable, Disposable
{
    @Inject
    private CacheManager cacheManager;

    private Cache<CacheEntry> cache;

    /**
     * Represent an entry of the configuration cache.
     * 
     * @version $Id$
     */
    public class CacheEntry
    {
        private final OIDCClientConfiguration configuration;

        /**
         * @param configuration the configuration
         */
        public CacheEntry(OIDCClientConfiguration configuration)
        {
            this.configuration = configuration;
        }

        /**
         * @return the configuration
         */
        public OIDCClientConfiguration getConfiguration()
        {
            return this.configuration;
        }
    }

    @Override
    public void initialize() throws InitializationException
    {
        try {
            this.cache = this.cacheManager.createNewCache(new LRUCacheConfiguration("oidc.client.configuration", 10));
        } catch (CacheException e) {
            throw new InitializationException("Failed to create cache with if [oidc.client.configuration]");
        }
    }

    @Override
    public void dispose() throws ComponentLifecycleException
    {
        this.cache.dispose();
    }

    /**
     * @param name the name of the configuration
     * @return the configuration
     */
    public CacheEntry get(String name)
    {
        return this.cache.get(name);
    }

    /**
     * @param name the configuration name
     * @param configuration the configuration
     */
    public void set(String name, OIDCClientConfiguration configuration)
    {
        this.cache.set(name, new CacheEntry(configuration));
    }

    /**
     * @param name the name of the configuration
     */
    public void invalidate(String name)
    {
        if (name != null) {
            this.cache.remove(name);
        }
    }

    /**
     * Empty the cache.
     */
    public void clear()
    {
        this.cache.removeAll();
    }
}
