package org.jenkinsci.plugins.api;

import org.scribe.builder.api.*;
import org.scribe.extractors.*;
import org.scribe.model.*;
import org.scribe.utils.*;

import org.jenkinsci.plugins.Globals;

public class UPMAuthentApi extends DefaultApi20
{
  private static final String AUTHORIZATION_URL = Globals.SERVICE_URL + "/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s";

  @Override
  public String getAccessTokenEndpoint()
  {
    return Globals.SERVICE_URL + "/oauth/token?grant_type=authorization_code";
  }

  @Override
  public String getAuthorizationUrl(OAuthConfig config)
  {
    return String.format(AUTHORIZATION_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
  }

  @Override
  public AccessTokenExtractor getAccessTokenExtractor()
  {
    return new JsonTokenExtractor();
  }
}