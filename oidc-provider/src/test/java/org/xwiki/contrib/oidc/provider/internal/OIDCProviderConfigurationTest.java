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
package org.xwiki.contrib.oidc.provider.internal;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.xwiki.configuration.internal.MemoryConfigurationSource;
import org.xwiki.test.annotation.BeforeComponent;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectComponentManager;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.mockito.MockitoComponentManager;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Validate {@link OIDCProviderConfiguration}.
 *
 * @version $Id$
 */
@ComponentTest
class OIDCProviderConfigurationTest
{
    @InjectComponentManager
    private MockitoComponentManager componentManager;

    @InjectMockComponents
    private OIDCProviderConfiguration configuration;

    private MemoryConfigurationSource source;

    @BeforeComponent
    void beforeComponent() throws Exception
    {
        this.source = this.componentManager.registerMemoryConfigurationSource();
    }

    @Test
    void getCORSAllowedOrigins()
    {
        assertEquals(List.of("*"), this.configuration.getCORSAllowedOrigins());

        this.source.setProperty(OIDCProviderConfiguration.PROP_CORS_ALLOWEDORIGINS,
            Arrays.asList(" https://a.example.com", "", "https://b.example.com "));
        assertEquals(List.of("https://a.example.com", "https://b.example.com"),
            this.configuration.getCORSAllowedOrigins());

        this.source.setProperty(OIDCProviderConfiguration.PROP_CORS_ALLOWEDORIGINS, List.of());
        assertEquals(List.of(), this.configuration.getCORSAllowedOrigins());
    }
}
