package org.jenkinsci.plugins.api;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;

import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
//import org.jenkinsci.plugins.api.UPMAuthentUser.UPMAuthentUserResponce;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import com.google.gson.Gson;

import org.jenkinsci.plugins.Globals;

public class UPMAuthentApiService {

    private OAuthService service;

    public UPMAuthentApiService(String serviceURL, String apiKey, String apiSecret) {
        this(serviceURL, apiKey, apiSecret, null);
    }

    public UPMAuthentApiService(String serviceURL, String apiKey, String apiSecret, String callback) {
        super();

        ServiceBuilder builder = new ServiceBuilder().provider(UPMAuthentApi.class).apiKey(apiKey).apiSecret(apiSecret);
        if (StringUtils.isNotBlank(callback)) {
            builder.callback(callback);
        }
        service = builder.build();
    }

    public Token createRquestToken() {
        return service.getRequestToken();
    }

    public String createAuthorizationCodeURL(Token requestToken) {
        return service.getAuthorizationUrl(requestToken);
    }

    public Token getTokenByAuthorizationCode(String code, Token requestToken) {
        Verifier v = new Verifier(code);

        return service.getAccessToken(requestToken, v);
    }

    public UPMAuthentUser getUserByToken(Token accessToken) {
        OAuthRequest request = new OAuthRequest(Verb.GET, Globals.SERVICE_URL + "/api/user.info.json");
        service.signRequest(accessToken, request);
        Response response = request.send();
        String json = response.getBody();
        Gson gson = new Gson();
        UPMAuthentUser userResponce = gson.fromJson(json, UPMAuthentUser.class);
        
        if (userResponce != null) {
            return userResponce;
        } else {
            return null;
        }
    }

    public UserDetails getUserByUsername(String username) {
        InputStreamReader reader = null;
        UPMAuthentUser userResponce = null;
        try {
            URL url = new URL(Globals.SERVICE_URL + "/api/users/" + java.net.URLEncoder.encode(username).replace("+", "%20") + ".json");
            
            reader = new InputStreamReader(url.openStream(), "UTF-8");
            Gson gson = new Gson();
            userResponce = gson.fromJson(reader, UPMAuthentUser.class);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            IOUtils.closeQuietly(reader);
        }

        if (userResponce != null) {
            return userResponce;
        } else {
            return null;
        }

    }

}
