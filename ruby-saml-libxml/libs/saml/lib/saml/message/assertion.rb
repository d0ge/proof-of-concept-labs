# typed: true
# frozen_string_literal: true

module SAML
  class Message
    class Assertion < Message
      include SAML::Shared::Issuer

      attr_accessor :id
      attr_accessor :destination
      attr_accessor :issue_instant
      attr_accessor :attributes
      attr_accessor :name_id
      attr_accessor :name_id_format
      attr_accessor :recipient
      attr_accessor :audience

      def initialize(options = {})
        super
        self.id ||= "_" + SecureRandom.hex(32)
        self.issue_instant ||= Time.now
        self.attributes ||= {}
      end

      def build_document
        Nokogiri::XML::Builder.new do |builder|
          decorate(builder)
        end.doc
      end

      def decorate(builder)
        root_attributes = {
          "xmlns:saml"      => "urn:oasis:names:tc:SAML:2.0:assertion",
          "ID"              => self.id,
          "IssueInstant"    => format_time(self.issue_instant),
          "Version"         => "2.0",
        }
        root_attributes["Destination"] = self.destination if self.destination.present?

        builder["saml"].Assertion(root_attributes) do
          generate_issuer(builder)

          if name_id.present?
            builder["saml"].Subject do
              if name_id_format.present?
                builder["saml"].NameID(name_id, "Format" => name_id_format)
              else
                builder["saml"].NameID(name_id)
              end

              if recipient.present?
                builder["saml"].SubjectConfirmation("Method" => "urn:oasis:names:tc:SAML:2.0:cm:bearer") do
                  builder["saml"].SubjectConfirmationData("Recipient" => recipient)
                end
              end
            end
          end

          if audience.present?
            builder["saml"].Conditions do
              builder["saml"].AudienceRestriction do
                builder["saml"].Audience(audience)
              end
            end
          end

          builder["saml"].AttributeStatement do
            attributes.each do |friendly_name, attribute_values|
              builder["saml"].Attribute({ "FriendlyName" => friendly_name, "Name" => "urn:oid:0.9.2342.19200300.100.1.1" }) do
                attribute_values.each do |attribute_value|
                  builder["saml"].AttributeValue(attribute_value)
                end
              end
            end
          end
        end
      end
    end
  end
end
