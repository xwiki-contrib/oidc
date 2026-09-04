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
package org.xwiki.contrib.oidc.consent.internal.store;

import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;

import com.xpn.xwiki.objects.BaseObjectReference;

/**
 * A token specific version of {@link BaseObjectReference}.
 * 
 * @version $Id$
 * @since 2.26.0
 */
public class ConsentReference extends BaseObjectReference
{
    private static final long serialVersionUID = 1L;

    /**
     * Create a version 2 reference, based on the reference of the document containing the consent and the number of
     * the consent xobject.
     *
     * @param documentReference the reference of the document containing the consent
     * @param number the number of the consent xobject
     */
    public ConsentReference(DocumentReference documentReference, int number)
    {
        super(new DocumentReference(BaseObjectOIDCConsent.REFERENCE, documentReference.getWikiReference()), number,
            documentReference);
    }

    /**
     * Create a version 1 reference, based on the reference of the consent xobject.
     *
     * @param objectReference the reference of the consent xobject
     */
    public ConsentReference(EntityReference objectReference)
    {
        super(objectReference);
    }
}
