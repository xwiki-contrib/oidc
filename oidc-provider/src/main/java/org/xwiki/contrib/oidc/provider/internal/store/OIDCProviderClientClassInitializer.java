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
import com.xpn.xwiki.objects.classes.ListClass;
import com.xpn.xwiki.objects.classes.StaticListClass;
import com.xpn.xwiki.objects.classes.TextAreaClass.ContentType;

/**
 * Initialize OIDC client class.
 * 
 * @version $Id: 9fbf4b627cd3716e8cd506e00b9c663f388a98f0 $
 */
@Component
@Named(BaseObjectOIDCClient.REFERENCE_STRING)
@Singleton
public class OIDCProviderClientClassInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Default constructor.
     */
    public OIDCProviderClientClassInitializer()
    {
        super(BaseObjectOIDCClient.REFERENCE, "XWiki OIDC Client Class");
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(BaseObjectOIDCClient.FIELD_ID, "Client ID", 30);
        xclass.addPasswordField(BaseObjectOIDCClient.FIELD_SECRET, "Client secret", 30);
        StaticListClass redirectURIs = xclass.addStaticListField(BaseObjectOIDCClient.FIELD_REDIRECT_URIS);
        redirectURIs.setMultiSelect(true);
        redirectURIs.setLargeStorage(true);
        redirectURIs.setRelationalStorage(true);
        redirectURIs.setPicker(false);
        redirectURIs.setSeparators(", ");
        redirectURIs.setDisplayType(ListClass.DISPLAYTYPE_INPUT);
        xclass.addTextAreaField(BaseObjectOIDCClient.FIELD_BACKCHANNEL_LOGOUT_URI, "Back-channel logout URI", 200, 1,
            ContentType.PURE_TEXT);
        xclass.addBooleanField(BaseObjectOIDCClient.FIELD_ENABLED, "Enabled", "checkbox", true);
    }
}
