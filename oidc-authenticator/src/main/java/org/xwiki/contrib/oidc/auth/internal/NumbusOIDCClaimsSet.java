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
package org.xwiki.contrib.oidc.auth.internal;

import java.util.ArrayList;
import java.util.List;

import org.xwiki.contrib.oidc.OIDCClaimsSet;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/**
 * Nimbus SDK based implementation of {@link OIDCClaimsSet}.
 * 
 * @param <C>
 * @version $Id$
 */
public class NumbusOIDCClaimsSet<C extends ClaimsSet> implements OIDCClaimsSet
{
    protected C claims;

    /**
     * @param claims the Nimbus SDK claims set
     */
    public NumbusOIDCClaimsSet(C claims)
    {
        this.claims = claims;
    }

    protected List<String> toStringList(List<?> list)
    {
        List<String> stringList = new ArrayList<>(list.size());

        for (Object value : list) {
            stringList.add(value.toString());
        }

        return stringList;
    }

    @Override
    public Object getClaim(String name)
    {
        return this.claims.getClaim(name);
    }

    @Override
    public <T> T getClaim(String name, Class<T> clazz)
    {
        return this.claims.getClaim(name, clazz);
    }
}
