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

import java.net.URI;

import javax.mail.internet.InternetAddress;

import org.xwiki.contrib.oidc.OIDCAddress;
import org.xwiki.contrib.oidc.OIDCUserInfo;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/**
 * Nimbus SDK based implementation of {@link OIDCUserInfo}.
 * 
 * @version $Id$
 * @since 1.2
 */
public class NimbusOIDCUserInfo extends NumbusOIDCClaimsSet<UserInfo> implements OIDCUserInfo
{
    /**
     * @param userInfo the Nimbus SDK user info
     */
    public NimbusOIDCUserInfo(UserInfo userInfo)
    {
        super(userInfo);
    }

    @Override
    public String getSubject()
    {
        return this.claims.getSubject().getValue();
    }

    @Override
    public String getName()
    {
        return this.claims.getName();
    }

    @Override
    public String getGivenName()
    {
        return this.claims.getGivenName();
    }

    @Override
    public String getFamilyName()
    {
        return this.claims.getFamilyName();
    }

    @Override
    public String getMiddleName()
    {
        return this.claims.getMiddleName();
    }

    @Override
    public String getNickname()
    {
        return this.claims.getNickname();
    }

    @Override
    public String getPreferredUsername()
    {
        return this.claims.getPreferredUsername();
    }

    @Override
    public URI getProfile()
    {
        return this.claims.getProfile();
    }

    @Override
    public URI getPicture()
    {
        return this.claims.getPicture();
    }

    @Override
    public URI getWebsite()
    {
        return this.claims.getWebsite();
    }

    @Override
    public InternetAddress getEmail()
    {
        return this.claims.getEmail();
    }

    @Override
    public Boolean getEmailVerified()
    {
        return this.claims.getEmailVerified();
    }

    @Override
    public String getGender()
    {
        return this.claims.getGender().getValue();
    }

    @Override
    public String getBirthdate()
    {
        return this.claims.getBirthdate();
    }

    @Override
    public String getZoneinfo()
    {
        return this.claims.getZoneinfo();
    }

    @Override
    public String getLocale()
    {
        return this.claims.getLocale();
    }

    @Override
    public String getPhoneNumber()
    {
        return this.claims.getPhoneNumber();
    }

    @Override
    public Boolean getPhoneNumberVerified()
    {
        return this.claims.getPhoneNumberVerified();
    }

    @Override
    public OIDCAddress getAddress()
    {
        return new NimbusOIDCAddress(this.claims.getAddress());
    }
}
