class SamlController < ApplicationController

  skip_before_action :verify_authenticity_token, only: [:acs, :process_logout_response]

  def index
    # Sets the redirect properties
    if params[:redirect]
      # Get the original, encoded redirect
      uri = URI.parse(request.url)
      orig_params = Hash[uri.query.split("&").map {|e| e.split("=",2)}].symbolize_keys
      session[:redirect] = orig_params[:redirect]
    else
      session[:redirect] = request.referer
    end

    redirect_to login_index_path
  end


  def login
    request = OneLogin::RubySaml::Authrequest.new
    redirect_to(request.create(saml_settings))
  end

  def metadata
    meta = OneLogin::RubySaml::Metadata.new
    render :xml => meta.generate(saml_settings), :content_type => "application/samlmetadata+xml"
  end

  def acs
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], :settings => saml_settings)

    @errors = []

    access_token = nil

    # We validate the SAML Response and check if the user already exists in the system
    if response.is_valid?(collectErrors=true)
      # authorize_success, log the user

      idpUser = Hash.new
      idpUser[:userid] = response.nameid
      idpUser[:emailAddress] = response.attributes["emailAddress"]
      idpUser[:firstName] = response.attributes["firstName"]
      idpUser[:lastName] = response.attributes["lastName"]

      assertionElement = response.document.get_elements("//saml2:Assertion")[0]
      (errors, access_token) = oauth2_access_token_request(assertionElement.to_s)

      if !errors.nil? && errors.length > 0
        @errors.append(*errors)
      end
    else
      @errors.append(*response.errors)
    end

    if !@errors.nil? && @errors.length > 0
      render :action => 'index'
    else
      ontoportalUser = LinkedData::Client::Models::User.find_by_username(idpUser[:userid])&.first

      if ontoportalUser.nil?
        ontoportalUser = LinkedData::Client::Models::User.new(values: {
                                                                username: idpUser[:userid],
          email: idpUser[:emailAddress],
          firstName: idpUser[:firstName],
          lastName: idpUser[:lastName],
          password: SecureRandom.hex(20) # we generate a random password, as we don't know the password in the IDP and we don't need it in any case
                                                              })
        saved_user = ontoportalUser.save
        unless saved_user.errors.nil?
          @errors.append(*saved_user.errors)
        end
        # Flush UI cache
        @cache = Rails.cache.instance_variable_get("@data")
        @cache.flush_all if @cache.respond_to?(:flush_all)
      end

      if @errors.nil? || @errors.length == 0
        Thread.current[:ontologies_api_client_token] = access_token

        logged_in_user = LinkedData::Client::HTTP.get("#{LinkedData::Client.settings.rest_url}/users/#{idpUser[:userid]}", { show_apikey: "true" }, {headers: {
          "Authorization": "Bearer #{access_token}"
                                     }})

        Thread.current[:ontologies_api_client_token] = nil

        loginInternal(logged_in_user)

        redirect = root_path

        if session[:redirect]
          redirect = CGI.unescape(session[:redirect])
        end

        redirect_to redirect
      else
        render :action => 'index'
      end
    end
  end

  def encode(string)
    if Base64.respond_to?('strict_encode64')
      Base64.strict_encode64(string)
    else
      Base64.encode64(string).gsub(/\n/, "")
    end
  end


  # Create a SP initiated SLO
  def sp_logout_request
    # LogoutRequest accepts plain browser requests w/o paramters
    settings = saml_settings

    if settings.idp_slo_service_url.nil?
      # SLO IdP Endpoint not found in settings, executing then a normal logout
      reset_session
      flash[:notice] = "You have successfully logged out from the system (locally)"
      redirect_to root_path
    else

      logout_request = OneLogin::RubySaml::Logoutrequest.new
      # New SP SLO for userid '#{session[:userid]}' transactionid '#{logout_request.uuid}'

      if settings.name_identifier_value.nil?
        settings.name_identifier_value = session[:user].username
      end

      # Ensure user is logged out before redirect to IdP, in case anything goes wrong during single logout process (as recommended by saml2int [SDP-SP34])
      logged_user = session[:user].username
      # Delete session for '#{logged_user}'"
      reset_session

      # Save the transaction_id to compare it with the response we get back
      session[:transaction_id] = logout_request.uuid
      session[:logged_out_user] = logged_user

      relayState = root_url

      redirect_to(logout_request.create(settings, :RelayState => relayState))
    end
  end

  # After sending an SP initiated LogoutRequest to the IdP, we need to accept
  # the LogoutResponse, verify it, then actually delete our session.
  def process_logout_response
    settings = saml_settings

    if session.has_key? :transaction_id
      logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], settings, :matches_request_id => session[:transaction_id])
    else
      logout_response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLResponse], settings)
    end

    # LogoutResponse is: #{logout_response.to_s}

    # Validate the SAML Logout Response
    if not logout_response.validate
      # logger.error "The SAML Logout Response is invalid"
    else
      # Actually log out this session
      # SLO completed for '#{session[:logged_out_user]}'
      reset_session
    end

    flash[:notice] = "You have successfully logged out from the system"
    redirect_to root_path
  end


  private

  def saml_settings
    idp_metadata_parser                          = OneLogin::RubySaml::IdpMetadataParser.new

    settings                                     = idp_metadata_parser.parse(IO.read(Rails.root.join("config/saml/idp-metadata.xml")))

    settings.assertion_consumer_service_url       = "#{request.protocol}#{request.host}:#{request.port}/saml/acs"
    settings.single_logout_service_url       = "#{request.protocol}#{request.host}:#{request.port}/saml/slo"
    settings.sp_entity_id                         = "#{request.protocol}#{request.host}:#{request.port}/saml/metadata"

    settings.certificate                    = IO.read(Rails.root.join("config/saml/sp_cert.pem"))
    settings.private_key                    = IO.read(Rails.root.join("config/saml/sp_key.pem"))

    settings.security[:authn_requests_signed]     = true  # Enable signature on AuthNRequest
    settings.security[:logout_requests_signed]    = true  # Enable signature on Logout Request
    settings.security[:logout_responses_signed]   = true  # Enable signature on Logout Response

    settings.idp_slo_target_url = settings.idp_slo_service_url # Is this fixing a bug?
    settings
  end

  def oauth2_access_token_request(assertionString)

    params = {
      "scope" => $OAUTH2_ECOPORTAL_SCOPE,
      "grant_type" => "urn:ietf:params:oauth:grant-type:saml2-bearer",
      "assertion" => encode(assertionString)
    }

    uri = URI(oauth2_settings[:token_request_endpoint])
    req = Net::HTTP::Post.new(uri)
    req.basic_auth oauth2_settings[:client_id], oauth2_settings[:client_secret]
    req.set_form(params)

    res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true, verify_mode: OpenSSL::SSL::VERIFY_NONE) {|http|
      http.request(req)
    }

    errors = []
    access_token = NIL

    if res.is_a?(Net::HTTPSuccess)
      access_token = JSON.parse(res.body)["access_token"]
    else
      errors << res.body
    end

    return errors, access_token
  end

  def loginInternal(user)
    return unless user
    session[:user] = user
    custom_ontologies_text = session[:user].customOntology && !session[:user].customOntology.empty? ? "The display is now based on your <a href='/account#custom_ontology_set'>Custom Ontology Set</a>." : ""
    notice = "Welcome <b>" + user.username.to_s + "</b>! " + custom_ontologies_text
    flash[:success] = notice.html_safe
  end

  def oauth2_settings
    settings = Hash.new
    settings[:token_request_endpoint] = $OAUTH2_AUTHORIZATION_SERVER + "oauth2/token"
    settings[:client_id] = Rails.application.credentials.oauth2[:client_id]
    settings[:client_secret] = Rails.application.credentials.oauth2[:client_secret]
    settings
  end
end