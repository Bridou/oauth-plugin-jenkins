package org.jenkinsci.plugins;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.api.UPMAuthentApiService;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.scribe.model.Token;
import org.scribe.model.Verifier;
import org.springframework.dao.DataAccessException;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;


public class UPMAuthentSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = UPMAuthentSecurityRealm.class.getName() + ".referer";
    private static final String ACCESS_TOKEN_ATTRIBUTE = UPMAuthentSecurityRealm.class.getName() + ".access_token";
    private static final Logger LOGGER = Logger.getLogger(UPMAuthentSecurityRealm.class.getName());
    private static final Token EMPTY_TOKEN = null;
    
    private String serviceURL;
    private String clientID;
    private String clientSecret;

    @DataBoundConstructor
    public UPMAuthentSecurityRealm(String serviceURL, String clientID, String clientSecret) {
        super();
        
        this.serviceURL = Util.fixEmptyAndTrim(serviceURL);
        this.clientID = Util.fixEmptyAndTrim(clientID);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);

    }

    public UPMAuthentSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "UPMAuthentSecurityRealm()");
    }

    /**
     * @return the serviceURL
     */
    public String getServiceURL() {
        return serviceURL;
    }
    
    /**
     * @param serviceURL the serviceURL to set
     */
    public void setServiceURL(String serviceURL) {
        this.serviceURL = serviceURL;
    }
    
    /**
     * @return the clientID
     */
    public String getClientID() {
        return clientID;
    }

    /**
     * @param clientID the clientID to set
     */
    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    /**
     * @return the clientSecret
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * @param clientSecret the clientSecret to set
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {

        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);
        
        String callback = request.getRootPath() + "/securityRealm/finishLogin";
        UPMAuthentApiService upmAuthentApiService = new UPMAuthentApiService(serviceURL, clientID, clientSecret, callback);
        return new HttpRedirect(upmAuthentApiService.createAuthorizationCodeURL(EMPTY_TOKEN));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("code");
        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }
        String callback = request.getRootPath() + "/securityRealm/finishLogin";
        Token accessToken = new UPMAuthentApiService(serviceURL, clientID, clientSecret, callback).getTokenByAuthorizationCode(code, EMPTY_TOKEN);

        if (!accessToken.isEmpty()) {

            UPMAuthentAuthenticationToken auth = new UPMAuthentAuthenticationToken(accessToken, serviceURL, clientID, clientSecret);
            SecurityContextHolder.getContext().setAuthentication(auth);
            User u = User.current();
            u.setFullName(auth.getName());

        } else {
            LOGGER.log(Level.SEVERE, "doFinishLogin() accessToken = null");
        }

        // redirect to referer
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityRealm.SecurityComponents(new AuthenticationManager() {
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof UPMAuthentAuthenticationToken) {
                    return authentication;
                }

                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
                throw new UsernameNotFoundException(username);
            }
        });
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails result = null;
        UPMAuthentAuthenticationToken authToken = (UPMAuthentAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        if (authToken == null) {
            throw new UsernameNotFoundException("UPMAuthentAuthenticationToken = null, no known user: " + username);
        }
        result = new UPMAuthentApiService(serviceURL, clientID, clientSecret).getUserByUsername(username);
        if (result == null) {
            throw new UsernameNotFoundException("User does not exist for login: " + username);
        }
        return result;
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
        throw new UsernameNotFoundException("groups not supported");
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    public static final class ConverterImpl implements Converter {

        public boolean canConvert(Class type) {
            return type == UPMAuthentSecurityRealm.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            UPMAuthentSecurityRealm realm = (UPMAuthentSecurityRealm) source;
            
            writer.startNode("serviceURL");
            writer.setValue(realm.getServiceURL());
            writer.endNode();
            
            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();
            
            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();
        }

        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

            String node = reader.getNodeName();

            reader.moveDown();

            UPMAuthentSecurityRealm realm = new UPMAuthentSecurityRealm();
          
            node = reader.getNodeName();

            String value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

            reader.moveDown();

            node = reader.getNodeName();

            value = reader.getValue();

            setValue(realm, node, value);

            reader.moveUp();

            if (reader.hasMoreChildren()) {
                reader.moveDown();

                node = reader.getNodeName();

                value = reader.getValue();

                setValue(realm, node, value);

                reader.moveUp();
            }
            return realm;
        }

        private void setValue(UPMAuthentSecurityRealm realm, String node, String value) {

            if (node.equalsIgnoreCase("clientid")) {
                realm.setClientID(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
            } else if (node.equalsIgnoreCase("serviceurl")) {
               realm.setServiceURL(value);                
               Globals.SERVICE_URL = realm.getServiceURL();
               
            } else {
                throw new ConversionException("invalid node value = " + node);
            }

        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getHelpFile() {
            return "/plugin/upm-authentication/help/help-security-realm.html";
        }

        @Override
        public String getDisplayName() {
            return "UPM Authentication Plugin";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }
    }

}
