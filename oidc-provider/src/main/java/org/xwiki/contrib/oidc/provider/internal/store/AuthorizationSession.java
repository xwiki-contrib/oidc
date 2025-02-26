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
package org.xwiki.contrib.oidc.provider.internal.store;

import java.io.Serializable;

import org.xwiki.model.reference.DocumentReference;

import com.nimbusds.openid.connect.sdk.Nonce;

/**
 * Expose the metadata associated with an authorization code.
 * <p>
 * It's serializable so that it can be dispatched to other cluster members.
 * 
 * @version $Id$
 * @since 2.14.0
 */
public class AuthorizationSession implements Serializable
{
    private static final long serialVersionUID = 1L;

    private final DocumentReference userReference;

    private final String nonce;

    /**
     * @param userReference the reference of the user
     * @param nonce the nonce
     */
    public AuthorizationSession(DocumentReference userReference, Nonce nonce)
    {
        this.userReference = userReference;
        this.nonce = nonce != null ? nonce.getValue() : null;
    }

    /**
     * @return the userReference
     */
    public DocumentReference getUserReference()
    {
        return this.userReference;
    }

    /**
     * @return the nonce
     */
    public String getNonce()
    {
        return this.nonce;
    }
}
