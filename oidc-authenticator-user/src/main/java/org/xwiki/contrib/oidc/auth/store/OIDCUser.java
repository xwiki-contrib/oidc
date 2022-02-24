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
package org.xwiki.contrib.oidc.auth.store;

import java.util.Arrays;

import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.objects.BaseObject;

/**
 * An helper wrapping a BaseObject to make easier to manipulate OIDC metadta stored in a user profile.
 * 
 * @version $Id$
 * @since 1.25
 */
public class OIDCUser
{
    /**
     * The String reference of the class defining the object which contains the OIDC metadata in the user profile.
     */
    public static final String CLASS_FULLNAME = "XWiki.OIDC.UserClass";

    /**
     * The reference of the class defining the object which contains the OIDC metadata in the user profile.
     */
    public static final LocalDocumentReference CLASS_REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "UserClass");

    /**
     * The name of the property containing the OIDC issuer.
     */
    public static final String FIELD_ISSUER = "issuer";

    /**
     * The name of the property containing the OIDC subject.
     */
    public static final String FIELD_SUBJECT = "subject";

    private final BaseObject xobject;

    /**
     * @param xobject the actual XWiki object
     */
    public OIDCUser(BaseObject xobject)
    {
        this.xobject = xobject;
    }

    /**
     * @return the issuer
     */
    public String getIssuer()
    {
        return this.xobject.getStringValue(FIELD_ISSUER);
    }

    /**
     * @param issuer the issuer
     */
    public void setIssuer(String issuer)
    {
        this.xobject.setStringValue(FIELD_ISSUER, issuer);
    }

    /**
     * @return the subject
     */
    public String getSubject()
    {
        return this.xobject.getStringValue(FIELD_SUBJECT);
    }

    /**
     * @param subject the subject
     */
    public void setSubject(String subject)
    {
        this.xobject.setStringValue(FIELD_SUBJECT, subject);
    }
}
