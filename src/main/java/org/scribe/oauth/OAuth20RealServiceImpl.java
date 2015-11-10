package org.scribe.oauth;

import org.scribe.builder.api.*;
import org.scribe.model.*;

import org.apache.commons.codec.binary.*;


public class OAuth20RealServiceImpl implements OAuthService
{
  private static final String VERSION = "2.0";
  
  private final DefaultApi20 api;
  private final OAuthConfig config;
  
  /**
   * Default constructor
   * 
   * @param api OAuth2.0 api information
   * @param config OAuth 2.0 configuration param object
   */
  public OAuth20RealServiceImpl(DefaultApi20 api, OAuthConfig config)
  {
    this.api = api;
    this.config = config;
  }

  /**
   * {@inheritDoc}
   */
  public Token getAccessToken(Token requestToken, Verifier verifier)
  {
    OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
    String authString = config.getApiKey() + ":" + config.getApiSecret();
    byte [] authStringBytes = authString.getBytes();
    request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(authStringBytes)));
    request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
    request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
    request.addBodyParameter(OAuthConstants.GRANT_TYPE, OAuthConstants.GRANT_TYPE_AUTH_CODE);
    if(config.hasScope()) request.addBodyParameter(OAuthConstants.SCOPE, config.getScope());
    Response response = request.send();
    return api.getAccessTokenExtractor().extract(response.getBody());
  }

  /**
   * {@inheritDoc}
   */
  public Token getRequestToken()
  {
    throw new UnsupportedOperationException("Unsupported operation, please use 'getAuthorizationUrl' and redirect your users there");
  }

  /**
   * {@inheritDoc}
   */
  public String getVersion()
  {
    return VERSION;
  }

  /**
   * {@inheritDoc}
   */
  public void signRequest(Token accessToken, OAuthRequest request)
  {
    request.addHeader("Authorization", "Bearer " + accessToken.getToken());
  }

  /**
   * {@inheritDoc}
   */
  public String getAuthorizationUrl(Token requestToken)
  {
    return api.getAuthorizationUrl(config);
  }

}
