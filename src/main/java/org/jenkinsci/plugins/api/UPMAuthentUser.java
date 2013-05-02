package org.jenkinsci.plugins.api;
import java.util.logging.Level;
import java.util.logging.Logger;
import hudson.security.SecurityRealm;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

import com.google.gson.annotations.SerializedName;


public class UPMAuthentUser implements UserDetails {

   private static final Logger LOGGER = Logger.getLogger(UPMAuthentUser.class.getName());

    @SerializedName("name")
    public String username;
    @SerializedName("firstname")
    public String firstName;
    @SerializedName("lastname")
    public String lastName;
    @SerializedName("email")
    public String email;    

    public UPMAuthentUser() {
        super();
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return new GrantedAuthority[] { SecurityRealm.AUTHENTICATED_AUTHORITY };
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {     
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
