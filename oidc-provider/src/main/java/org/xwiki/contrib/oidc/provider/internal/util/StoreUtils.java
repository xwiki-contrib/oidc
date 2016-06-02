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
package org.xwiki.contrib.oidc.provider.internal.util;

import java.util.ArrayList;
import java.util.List;

import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

public class StoreUtils
{
    // TODO: remove this workaround when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
    public static <T extends BaseObject> T getCustomObject(XWikiDocument document, EntityReference reference,
        Integer number, Class<T> customClass)
    {
        BaseObject obj = document.getXObject(reference, number);

        return convertObject(document, obj, customClass);
    }

    // TODO: remove this workaround when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
    public static <T extends BaseObject> List<T> getCustomObjects(XWikiDocument document,
        EntityReference classReference, Class<T> customClass)
    {
        List<BaseObject> objects = new ArrayList<>(document.getXObjects(classReference));

        for (int i = 0; i < objects.size(); ++i) {
            BaseObject obj = objects.get(i);
            if (obj != null) {
                objects.set(i, convertObject(document, obj, customClass));
            }
        }

        return (List) objects;
    }

    // TODO: remove this workaround when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
    public static <T extends BaseObject> T convertObject(XWikiDocument document, BaseObject obj, Class<T> customClass)
    {
        T customObject;

        if (customClass.isInstance(obj)) {
            customObject = customClass.cast(obj);
        } else if (obj != null) {
            // TODO: remove this workaround when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
            try {
                customObject = customClass.newInstance();
            } catch (Exception e) {
                // Should not happen
                return null;
            }

            // copy metadata
            customObject.setOwnerDocument(document);
            customObject.setXClassReference(obj.getXClassReference());
            customObject.setNumber(obj.getNumber());

            // copy values
            customObject.apply(obj, false);
            document.setXObject(customObject.getNumber(), customObject);
        } else {
            customObject = null;
        }

        return customObject;
    }

    // TODO: remove this workaround when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
    public static <T extends BaseObject> T getCustomObject(XWikiDocument document,
        LocalDocumentReference classReference, boolean create, XWikiContext xcontext, Class<T> customClass)
    {
        return convertObject(document, document.getXObject(classReference, create, xcontext), customClass);
    }

    // TODO: remove this workaround when http://jira.xwiki.org/browse/XWIKI-13456 is fixed
    public static <T extends BaseObject> T newCustomObject(XWikiDocument document, EntityReference classReference,
        XWikiContext context, Class<T> customClass) throws XWikiException
    {
        return convertObject(document, document.newXObject(classReference, context), customClass);
    }
}
