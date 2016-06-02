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

import java.util.Date;
import java.util.List;

import org.xwiki.contrib.oidc.OIDCIdToken;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Nimbus SDK based implementation of {@link OIDCIdToken}.
 * 
 * @version $Id$
 * @since 1.2
 */
public class NimbusOIDCIdToken extends NumbusOIDCClaimsSet<IDTokenClaimsSet> implements OIDCIdToken
{
    /**
     * @param idToken the Nimbus SDK id token
     */
    public NimbusOIDCIdToken(IDTokenClaimsSet idToken)
    {
        super(idToken);
    }

    @Override
    public String getIssuer()
    {
        return this.claims.getIssuer().getValue();
    }

    @Override
    public String getSubject()
    {
        return this.claims.getSubject().getValue();
    }

    @Override
    public List<String> getAudience()
    {
        return toStringList(this.claims.getAudience());
    }

    @Override
    public Date getExpirationTime()
    {
        return this.claims.getExpirationTime();
    }

    @Override
    public Date getIssueTime()
    {
        return this.claims.getIssueTime();
    }

    @Override
    public Date getAuthenticationTime()
    {
        return this.claims.getAuthenticationTime();
    }

    @Override
    public String getNonce()
    {
        return this.claims.getNonce().getValue();
    }

    @Override
    public String getAccessTokenHash()
    {
        return this.claims.getAccessTokenHash().getValue();
    }

    @Override
    public String getCodeHash()
    {
        return this.claims.getCodeHash().getValue();
    }

    @Override
    public String getACR()
    {
        return this.claims.getACR().getValue();
    }

    @Override
    public List<String> getAMR()
    {
        return toStringList(this.claims.getAMR());
    }

    @Override
    public String getAuthorizedParty()
    {
        return this.claims.getAuthorizedParty().getValue();
    }
}
