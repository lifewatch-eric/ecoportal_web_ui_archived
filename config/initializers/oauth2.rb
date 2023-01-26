if $SSO_ENABLED
  Oauth2Controller.config do |config|
    config.client_id = 'ecoportal-web-ui'
    config.client_secret = 'uDfeD3D0UsKfCLKLWVmdfUMsTH891dbm'
    config.authorize_redirect_uri = 'http://localhost:8080/oauth2/authorize_callback'
    config.host = 'localhost'
    config.authorization_endpoint = 'http://localhost:8080:8080/realms/xxxx/protocol/openid-connect/auth'
    config.token_endpoint = 'http://localhost:8080:8080/realms/xxxx/protocol/openid-connect/token'
    config.userinfo_endpoint = 'http://localhost:8080:8080/realms/xxxx/protocol/openid-connect/userinfo'
    config.logout_endpoint = 'http://localhost:8080:8080/realms/xxxx/protocol/openid-connect/logout'
  end
end
