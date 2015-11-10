package org.scribe.builder.api;

import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.JsonTokenExtractor;
import org.scribe.model.*;

import org.scribe.oauth.OAuth20RealServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.*;

public class MySrcmProdApi extends DefaultApi20
{
  private static final String AUTHORIZE_URL = "https://profile.sahajmarg.org/o/authorize/?client_id=%s&redirect_uri=%s&response_type=code";
  private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL + "&scope=%s";

  @Override
  public String getAccessTokenEndpoint()
  {
    return "https://profile.sahajmarg.org/o/token/";
  }

  @Override
  public Verb getAccessTokenVerb()
  {
    return Verb.POST;
  }

  @Override
  public String getAuthorizationUrl(OAuthConfig config)
  {
    Preconditions.checkValidUrl(config.getCallback(), "Must provide a valid url as callback. MySrcm does not support OOB");

    // Append scope if present
    if(config.hasScope())
    {
     return String.format(SCOPED_AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()), OAuthEncoder.encode(config.getScope()));
    }
    else
    {
      return String.format(AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
    }
  }

  @Override
  public OAuthService createService(OAuthConfig config)
  {
    return new OAuth20RealServiceImpl(this, config);
  }

  @Override
  public AccessTokenExtractor getAccessTokenExtractor() {
    return new JsonTokenExtractor();
  }
}