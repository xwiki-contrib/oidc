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

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * OpenID Connect related error.
 *
 * @version $Id: f143406561f7852ec1256fc17fc983bafd97cd0c $
 */
public class OIDCException extends Exception
{
    /**
     * Serialization identifier.
     */
    private static final long serialVersionUID = 1L;

    private final ErrorObject error;

    /**
     * Constructs a new exception with the specified detail message. The cause is not initialized, and may subsequently
     * be initialized by a call to {@link #initCause(Throwable)}.
     *
     * @param message the detail message (which is saved for later retrieval by the {@link #getMessage()} method)
     */
    public OIDCException(String message)
    {
        this(message, (ErrorObject) null);
    }

    /**
     * Constructs a new exception with the specified detail message. The cause is not initialized, and may subsequently
     * be initialized by a call to {@link #initCause(Throwable)}.
     *
     * @param message the detail message (which is saved for later retrieval by the {@link #getMessage()} method)
     * @param error error object, used to encapsulate OAuth 2.0 and other errors.
     */
    public OIDCException(String message, ErrorObject error)
    {
        super(error != null ? message + ':' + error.toString() : message);

        this.error = error;
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval by the {@link #getMessage()} method)
     * @param cause the cause (which is saved for later retrieval by the {@link #getCause()} method). A null value is
     *            permitted, and indicates that the cause is nonexistent or unknown
     */
    public OIDCException(String message, Throwable cause)
    {
        super(message, cause);

        this.error = null;
    }

    /**
     * @return error object, used to encapsulate OAuth 2.0 and other errors.
     */
    public ErrorObject getError()
    {
        return this.error;
    }
}
