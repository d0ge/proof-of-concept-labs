require 'sinatra'
require 'onelogin/ruby-saml'

# Set your SAML settings
def saml_settings
  settings = OneLogin::RubySaml::Settings.new

  settings.assertion_consumer_service_url = "http://sp.example.com/demo1/index.php?acs"
  settings.issuer                         = "http://sp.example.com/demo1/metadata.php"
  settings.idp_sso_target_url            = "http://sp.example.com/demo1/metadata.php"
  settings.idp_cert                      = File.read("certs/idp_cert.pem")
  settings
end

# Show home
get '/' do
  <<-HTML
    <h1>Ruby SAML Demo</h1>
    <a href="/login">Login via SAML</a>
  HTML
end

# Initiate SAML login
get '/login' do
  request = OneLogin::RubySaml::Authrequest.new
  redirect request.create(saml_settings)
end

post '/saml/acs' do
  response = OneLogin::RubySaml::Response.new(
    params[:SAMLResponse],
    settings: saml_settings,
    allowed_clock_drift: 60 * 60 * 24 * 365,  # 1 year drift
    skip_conditions: true,
    skip_subject_confirmation: true,
    soft: false
  )

  if response.is_valid?
    attrs = response.attributes
    output = ["SAML Response is valid."]

    output << "Welcome: #{response.nameid}"

    if attrs.to_h.empty?
      output << "No attributes found."
    else
      output << "Attributes:"
      attrs.to_h.each do |name, value|
        output << "#{name}: #{value}"
      end
    end
    output.join("\n")
  else
    status 403
    "SAML Response is invalid:\n" + response.errors.join("\n")
  end
end



# Optional: SP metadata for IdP setup
get '/metadata' do
  metadata = OneLogin::RubySaml::Metadata.new
  content_type 'application/xml'
  metadata.generate(saml_settings, true)
end
