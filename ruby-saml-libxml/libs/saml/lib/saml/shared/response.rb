# typed: true
# frozen_string_literal: true

module SAML
  module Shared
    module Response

      include Request
      attr_accessor :in_response_to 
      attr_accessor :recipient
      attr_accessor :audience

    end
  end
end
