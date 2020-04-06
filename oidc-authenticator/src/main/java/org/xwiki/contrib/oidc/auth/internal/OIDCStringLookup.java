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

import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.lookup.StringLookup;
import org.apache.commons.text.lookup.StringLookupFactory;

/**
 * Wrap a {@link StringLookup} and return empty string instead of null.
 * 
 * @version $Id$
 * @since 1.19
 */
public class OIDCStringLookup implements StringLookup
{
    private final StringLookup lookup;

    /**
     * @param valueMap the map with the variables' values
     */
    public OIDCStringLookup(final Map<String, String> valueMap)
    {
        this.lookup = StringLookupFactory.INSTANCE.mapStringLookup(valueMap);
    }

    @Override
    public String lookup(String key)
    {
        return StringUtils.defaultString(this.lookup.lookup(key));
    }
}
