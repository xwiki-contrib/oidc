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
package org.xwiki.contrib.oidc.auth.internal.store;

import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.mandatory.AbstractMandatoryDocumentInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;

@Component
@Named(OIDCUser.CLASS_FULLNAME)
@Singleton
public class OIDCUserClassDocumentInitializer extends AbstractMandatoryDocumentInitializer
{
    /**
     * Default constructor.
     */
    public OIDCUserClassDocumentInitializer()
    {
        super(OIDCUser.CLASS_REFERENCE);
    }

    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        boolean needsUpdate = false;

        BaseClass bclass = document.getXClass();

        String customClass = OIDCUser.class.getName();
        if (!customClass.equals(bclass.getCustomClass())) {
            bclass.setCustomClass(customClass);
            needsUpdate = true;
        }

        needsUpdate |= bclass.addTextField(OIDCUser.FIELD_ISSUER, "Issuer", 30);
        needsUpdate |= bclass.addTextField(OIDCUser.FIELD_SUBJECT, "Subject", 30);

        needsUpdate |= setClassDocumentFields(document, "OpenID Connect User Class");

        return needsUpdate;
    }
}
