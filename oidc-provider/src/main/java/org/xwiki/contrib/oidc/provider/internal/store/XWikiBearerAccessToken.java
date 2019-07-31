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

import java.security.SecureRandom;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

/**
 * Extends {@link BearerAccessToken} with the reference of the consent object.
 * 
 * @version $Id$
 * @since 1.15
 */
public class XWikiBearerAccessToken extends BearerAccessToken
{
    private static final SecureRandom SECURERANDOM = new SecureRandom();

    private final String objectReference;

    private final String random;

    protected XWikiBearerAccessToken(String objectReference, String random)
    {
        super(objectReference + '/' + random);

        this.objectReference = objectReference;
        this.random = random;
    }

    /**
     * @param objectReference the reference of the object containing the consent
     * @return the new {@link XWikiBearerAccessToken} instance
     */
    public static XWikiBearerAccessToken create(String objectReference)
    {
        byte[] n = new byte[32];
        SECURERANDOM.nextBytes(n);

        return new XWikiBearerAccessToken(objectReference, Base64URL.encode(n).toString());
    }

    /**
     * @param token the complete token value
     * @return the parsed {@link XWikiBearerAccessToken} instance
     * @throws ParseException when the token string is invalid
     */
    public static XWikiBearerAccessToken parse(String token) throws ParseException
    {
        BearerAccessToken accessToken = BearerAccessToken.parse(token);

        return parse(accessToken);
    }

    /**
     * @param token the complete token value
     * @return the parsed {@link XWikiBearerAccessToken} instance
     */
    public static XWikiBearerAccessToken parse(AccessToken token)
    {
        String tokenValue = token.getValue();
        int index = tokenValue.lastIndexOf('/');

        if (index == -1) {
            return null;
        }

        String objectReference = tokenValue.substring(0, index);
        String random = tokenValue.substring(index + 1);

        return new XWikiBearerAccessToken(objectReference, random);
    }

    /**
     * @return the reference of the object containing the consent
     */
    public String getObjectReference()
    {
        return this.objectReference;
    }

    /**
     * @return the random value
     */
    public String getRandom()
    {
        return this.random;
    }
}
