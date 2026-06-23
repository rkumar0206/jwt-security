package com.rksdev.security.api;

/**
 * Interface to be implemented by custom UserDetails objects in the host application
 * to expose the internal database numeric User ID to the security library.
 */
public interface IdentifiableUser {
    Long getUserId();
}