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
package org.xwiki.contrib.oidc.auth.internal.session;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

/**
 * @version $Id$
 */
@Component(roles = ClientProviders.class)
@Singleton
public class ClientProviders
{
    /**
     * Contains information about a provider.
     * 
     * @version $Id$
     */
    public class ClientProvider
    {
        private final URI discoveryURI;

        private OIDCProviderMetadata metadata;

        private ClientID clientID;

        /**
         * @param discoveryURI the URI of the discovery endpoint
         * @param metadata the metadata
         * @param clientID the client ID provided by the provider
         * @since 2.26.0
         */
        public ClientProvider(URI discoveryURI, OIDCProviderMetadata metadata, ClientID clientID)
        {
            this.discoveryURI = discoveryURI;
            this.metadata = metadata;
            this.clientID = clientID;
        }

        /**
         * @return the URI of the discovery endpoint
         * @since 2.26.0
         */
        public URI getDiscoveryURI()
        {
            return this.discoveryURI;
        }

        /**
         * @return the metadata
         */
        public OIDCProviderMetadata getMetadata()
        {
            return this.metadata;
        }

        /**
         * @return the clientID
         */
        public ClientID getClientID()
        {
            return this.clientID;
        }

        /**
         * @param clientID the clientID to set
         */
        public void setClientID(ClientID clientID)
        {
            this.clientID = clientID;
        }
    }

    private final Map<URI, ClientProvider> providers = new ConcurrentHashMap<>();

    /**
     * @param discoveryURI the URI of the discovery endpoint
     * @return the {@link ClientProvider} instance
     * @since 2.26.0
     */
    public ClientProvider getClientProvider(URI discoveryURI)
    {
        return this.providers.get(discoveryURI);
    }

    /**
     * @param discoveryURI the URI of the discovery endpoint
     * @param metadata the metadata
     * @param clientID the client ID provider by the provider
     * @return the new {@link ClientProvider}
     * @since 2.26.0
     */
    public ClientProvider setClientProvider(URI discoveryURI, OIDCProviderMetadata metadata, ClientID clientID)
    {
        ClientProvider clientProvider = new ClientProvider(discoveryURI, metadata, clientID);

        this.providers.put(discoveryURI, clientProvider);

        return clientProvider;
    }
}
