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

import java.util.Arrays;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.mandatory.AbstractMandatoryDocumentInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;

/**
 * Initialize OIDC class.
 * 
 * @version $Id: 9fbf4b627cd3716e8cd506e00b9c663f388a98f0 $
 */
@Component
@Named(OIDCConsentClassDocumentInitializer.REFERENCE_STRING)
@Singleton
public class OIDCConsentClassDocumentInitializer extends AbstractMandatoryDocumentInitializer
{
    /**
     * The reference of the class as String.
     */
    public static final String REFERENCE_STRING = "XWiki.OIDC.ConsentClass";

    /**
     * The reference of the class.
     */
    public static final LocalDocumentReference REFERENCE =
        new LocalDocumentReference(Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "ConsentClass");

    /**
     * Default constructor.
     */
    public OIDCConsentClassDocumentInitializer()
    {
        super(REFERENCE);
    }

    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        boolean needsUpdate = false;

        BaseClass bclass = document.getXClass();

        // FIXME: uncomment when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
        /*String customClass = OIDCConsent.class.getName();
        if (!customClass.equals(bclass.getCustomClass())) {
            bclass.setCustomClass(customClass);
            needsUpdate = true;
        }*/

        needsUpdate |= bclass.addTextField(OIDCConsent.FIELD_CLIENTID, "Client ID", 30);
        needsUpdate |= bclass.addTextField(OIDCConsent.FIELD_REDIRECTURI, "Redirect URI", 30);
        needsUpdate |= bclass.addTextField(OIDCConsent.FIELD_AUTHORIZATIONCODE, "Authorization Code", 30);
        needsUpdate |= bclass.addTextField(OIDCConsent.FIELD_ACCESSTOKEN, "Access Token", 30);
        needsUpdate |= bclass.addBooleanField(OIDCConsent.FIELD_ALLOW, "Allow/Deny", "allow");

        needsUpdate = setClassDocumentFields(document, "XWiki OIDC Consent Class");

        return needsUpdate;
    }
}
