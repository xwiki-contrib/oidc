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

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;

/**
 * Extends {@link BearerAccessToken} with the reference of the consent object.
 * <p>
 * When serialize to an HTTP Authorization header:
 *
 * <pre>
 * Authorization: Bearer xwiki:XWiki.MyUser^XWiki.XWikiUsers[4]/2YotnFZFEjr1zCsicMWpAA
 * </pre>
 * 
 * @version $Id$
 * @since 1.15
 */
public class XWikiBearerAccessToken extends BearerAccessToken
{
    private final String objectReference;

    private final String random;

    private Date expiration;

    /**
     * @since 2.13.0
     */
    protected XWikiBearerAccessToken(String objectReference, String random, long lifetime)
    {
        this(objectReference, random, Date.from(Instant.now().plusSeconds(lifetime)));
    }

    /**
     * @since 2.13.0
     */
    protected XWikiBearerAccessToken(String objectReference, String random, Date expiration)
    {
        super(objectReference + '/' + random);

        this.objectReference = objectReference;
        this.random = random;
        this.expiration = expiration;
    }

    private static String newRandom()
    {
        byte[] n = new byte[DEFAULT_BYTE_LENGTH];
        secureRandom.nextBytes(n);

        return Base64URL.encode(n).toString();
    }

    /**
     * @param documentObjectReference the reference of the object containing the consent
     * @param expiration the expiration date
     * @return the new {@link XWikiBearerAccessToken} instance
     * @since 2.13.0
     */
    public static XWikiBearerAccessToken create(String documentObjectReference, Date expiration)
    {

        return new XWikiBearerAccessToken(documentObjectReference, newRandom(), expiration);
    }

    /**
     * @param documentObjectReference the reference of the object containing the consent
     * @param lifetime the lifetime in seconds, 0 if not specified
     * @return the new {@link XWikiBearerAccessToken} instance
     * @since 2.13.0
     */
    public static XWikiBearerAccessToken create(String documentObjectReference, long lifetime)
    {
        return new XWikiBearerAccessToken(documentObjectReference, newRandom(), lifetime);
    }

    /**
     * @return the expiration date
     * @since 2.13.0
     */
    public Date getExpiration()
    {
        return this.expiration;
    }

    @Override
    public long getLifetime()
    {
        long lifetime = 0L;

        if (this.expiration != null) {
            lifetime = Duration.ofMillis(this.expiration.getTime() - new Date().getTime()).getSeconds();
        }

        return lifetime;
    }

    /**
     * @return the reference of the object containing the consent
     */
    public String getDocumentObjectReference()
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

    /**
     * @param documentObjectReference the reference of the object containing the consent
     * @return the new {@link XWikiBearerAccessToken} instance
     * @since 2.13.0
     */
    public static XWikiBearerAccessToken create(String documentObjectReference)
    {
        return create(documentObjectReference, 0L);
    }

    /**
     * @param authorization the HTTP authorization header value
     * @return the parsed {@link XWikiBearerAccessToken}, or null if not a supported type
     * @throws ParseException when failing to parse the token
     * @since 2.13.0
     */
    public static XWikiBearerAccessToken parse(String authorization) throws ParseException
    {
        BearerAccessToken accessToken = BearerAccessToken.parse(authorization);

        return parse(accessToken);
    }

    /**
     * @param token the complete token value
     * @return the parsed {@link XWikiBearerAccessToken} instance
     */
    public static XWikiBearerAccessToken parse(AccessToken token) throws ParseException
    {
        String tokenValue = token.getValue();
        int index = tokenValue.lastIndexOf('/');

        if (index == -1) {
            throw new ParseException(
                "The token value [" + tokenValue + "] does not have the expected format (<object reference>/<random>)");
        }

        String objectReference = tokenValue.substring(0, index);
        String random = tokenValue.substring(index + 1);

        return new XWikiBearerAccessToken(objectReference, random, null);
    }
}
