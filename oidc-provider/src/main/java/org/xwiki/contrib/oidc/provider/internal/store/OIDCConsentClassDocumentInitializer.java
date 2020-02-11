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

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;

/**
 * Initialize OIDC class.
 * 
 * @version $Id: 9fbf4b627cd3716e8cd506e00b9c663f388a98f0 $
 */
@Component
@Named(OIDCConsent.REFERENCE_STRING)
@Singleton
public class OIDCConsentClassDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Default constructor.
     */
    public OIDCConsentClassDocumentInitializer()
    {
        super(OIDCConsent.REFERENCE, "XWiki OIDC Consent Class");
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        // Use custom class to make easier to manipulate consent objects
        xclass.setCustomClass(OIDCConsent.class.getName());

        xclass.addTextField(OIDCConsent.FIELD_CLIENTID, "Client ID", 30);
        xclass.addTextField(OIDCConsent.FIELD_REDIRECTURI, "Redirect URI", 30);
        xclass.addBooleanField(OIDCConsent.FIELD_ALLOW, "Allow/Deny", "allow");
        xclass.addTextAreaField(OIDCConsent.FIELD_CLAIMS, "Claims", 60, 10);
        xclass.addPasswordField(OIDCConsent.FIELD_ACCESSTOKEN, "Access Token", 30);
    }
}
