# typed: true
# frozen_string_literal: true
require 'time'
require "nokogiri"
require "securerandom"
require "scientist"

require "saml/shared/issuer"
require "saml/shared/request"
require "saml/shared/response"
require "saml/shared/status"

require "saml/message"
require "saml/message/assertion"
require "saml/message/response"

module SAML
  extend self
end