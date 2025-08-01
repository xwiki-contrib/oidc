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
package org.xwiki.contrib.oidc.internal;

import java.util.Optional;

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
import org.xwiki.contrib.oidc.OAuth2Token;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;

/**
 * Cache for OAuth token store.
 *
 * @version $Id$
 * @since 2.19.2
 */
@Component(roles = OAuth2TokenStoreCache.class)
@Singleton
public class OAuth2TokenStoreCache implements Initializable, Disposable
{
    private static final String CACHE_KEY_SEPARATOR = "_";

    @Inject
    private CacheManager cacheManager;

    private Cache<Optional<OAuth2Token>> cache;

    @Inject
    private EntityReferenceSerializer<String> serializer;

    @Override
    public void initialize() throws InitializationException
    {
        try {
            this.cache = this.cacheManager.createNewCache(new LRUCacheConfiguration("oidc.client.token", 1000));
        } catch (CacheException e) {
            throw new InitializationException("Failed to create cache with if [oidc.client.token]");
        }
    }

    @Override
    public void dispose() throws ComponentLifecycleException
    {
        this.cache.dispose();
    }

    /**
     * Get the token from the cache if it exists.
     *
     * @param documentReference the document reference of the related token (where the token is stored).
     * @param configurationName the configuration name of the related token.
     * @return the token if it exists in the cache. Note that if {@code Optional.empty()} is returned, it will mean that
     *     we have a cache entry for this configuration, but we don't have any token for this configuration. If
     *     {@code null} is returned, it means that we don't have a cache entry for this configuration and the value need
     *     to be got from the original document.
     */
    public Optional<OAuth2Token> get(DocumentReference documentReference, String configurationName)
    {
        String cacheKey = getCacheKey(documentReference, configurationName);
        return cache.get(cacheKey);
    }

    /**
     * Add a new token into the cache.
     *
     * @param token the token to add in the cache. Could be {@code Optional.empty()} to mean that we don't have any
     *     token for this configuration.
     * @param documentReference the document reference of the related token (where the token is stored).
     * @param configurationName the configuration name of the related token.
     */
    public void add(Optional<OAuth2Token> token, DocumentReference documentReference, String configurationName)
    {
        String cacheKey = getCacheKey(documentReference, configurationName);
        cache.set(cacheKey, token);
    }

    /**
     * Invalidate the corresponding cache.
     *
     * @param documentReference the reference of the document which changed and need to be removed from the cache.
     * @param configurationName the configuration name of the related token.
     */
    public void invalidateCache(DocumentReference documentReference, String configurationName)
    {
        String name = getCacheKey(documentReference, configurationName);
        this.cache.remove(name);
    }

    /**
     * Clean all entry in the token store cache.
     */
    public void clearCache()
    {
        this.cache.removeAll();
    }

    private String getCacheKey(DocumentReference documentReference, String configurationName)
    {
        return serializer.serialize(documentReference) + CACHE_KEY_SEPARATOR
            // Escape "_" with "\" to avoid any collisions
            + configurationName.replace("\\", "\\\\").replace(CACHE_KEY_SEPARATOR, "\\_");
    }
}
