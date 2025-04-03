# typed: true
# frozen_string_literal: true

module SAML
  module Shared

    module Request

      attr_accessor :id             
      attr_accessor :version        
      attr_accessor :issue_instant  
      attr_accessor :destination    
      attr_accessor :consent        

      def initialize(options = {})
        super
        self.id ||= ("_" + SecureRandom.hex(32))
        self.issue_instant ||= Time.now
        self.version ||= "2.0"
      end
    end
  end
end
