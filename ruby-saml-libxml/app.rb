require 'sinatra'
require 'erb'
require 'bundler/setup'
require 'xmldsig'
require 'saml'
require 'base64'
require 'cgi'

# Onelogin cert 
def base64cert
  "-----BEGIN CERTIFICATE-----
MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czET
MBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYD
VQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEy
NTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQK
DAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp
+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbti
a0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BM
KU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYD
VR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/D
Ee98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNy
TwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==
-----END CERTIFICATE-----"
end

def get_auth_failure_result(saml_response)
  errors = []

  unless saml_response.valid?(
    issuer: "http://idp.example.com/metadata.php",
    idp_certificate: base64cert,
    sp_url: "http://sp.example.com/demo1/metadata.php",
    dst_url: "http://sp.example.com/demo1/index.php?acs"
  )
    errors << "failure - Invalid SAML response"
  end

  if saml_response.request_denied?
    errors << "failure - RequestDenied"
  end

  unless saml_response.success?
    errors << "failure - Not Seccusesfull"
  end

  saml_response.errors.each do |error|
    errors << "SAML Error: #{error}"
  end

  errors.empty? ? nil : errors
end

enable :sessions

get '/' do
  erb :index
end

post '/sso/acs' do
  enc = params[:SAMLResponse]
  options = {}
  failure_result = nil
  saml_response = nil

  begin
    saml_response = ::SAML::Message::Response.from_param(enc, options)
    failure_result = get_auth_failure_result(saml_response)
  rescue => err
    failure_result = ["failure - Invalid SAML response - #{err.message}"]
  end

  if failure_result
    status 401
    return "<h2>Unauthorised</h2><ul>" + failure_result.map { |e| "<li>#{e}</li>" }.join + "</ul>"
  else
    session[:username] = saml_response.name_id
    redirect '/user'
  end
end

get '/user' do
  @username = session[:username]
  if @username
    erb :user
  else
    redirect '/'
  end
end
