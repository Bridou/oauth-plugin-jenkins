package org.jenkinsci.plugins;

import hudson.security.SecurityRealm;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.api.UPMAuthentApiService;
import org.jenkinsci.plugins.api.UPMAuthentUser;
import org.scribe.model.Token;

import java.util.*;

public class UPMAuthentAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -7826610577724673531L;

    private Token accessToken;
    private UPMAuthentUser upmAuthentUser;

    public UPMAuthentAuthenticationToken(Token accessToken, String serviceURL, String apiKey, String apiSecret) {
        this.accessToken = accessToken;
        this.upmAuthentUser = new UPMAuthentApiService(serviceURL, apiKey, apiSecret).getUserByToken(accessToken);
        
        boolean authenticated = false;

        if (upmAuthentUser != null) {
            authenticated = true;
        }

        setAuthenticated(authenticated);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return this.upmAuthentUser != null ? this.upmAuthentUser.getAuthorities() : new GrantedAuthority[0];
    }


    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }

    @Override
    public String getName() {
        return (upmAuthentUser != null ? upmAuthentUser.getUsername() : null);
    }

}
