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
package org.xwiki.contrib.oidc;

/**
 * Generic claims set.
 * 
 * @version $Id$
 * @since 1.2
 * @see OIDCIdToken
 * @see OIDCUserInfo
 */
public interface OIDCClaimsSet
{
    /**
     * Gets a claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified.
     */
    Object getClaim(String name);

    /**
     * Gets a claim that casts to the specified class.
     *
     * @param <T> the type to return
     * @param name The claim name. Must not be {@code null}.
     * @param clazz The Java class that the claim value should cast to. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or casting failed.
     */
    <T> T getClaim(String name, Class<T> clazz);

    // TODO: add support for lang tag
}
