# typed: true
# frozen_string_literal: true

require "base64"
require "uri"
require "nokogiri"
require "zlib"
require "tempfile"

module SAML
  class Message
    SCHEMA_DIR = File.expand_path("../schemas", __FILE__)

    class SigningError < RuntimeError; end

    def self.subclasses
      @subclasses ||= {}
    end

    def saml_encrypted_assertions?
      false
    end

    def self.inherited(klass)
      subclasses[klass.name.split("::").last] = klass
    end

    def self.build(xml, options = {})
      doc = Nokogiri::XML(xml)
      doc = Nokogiri::XML("<unknown />") unless doc.root

      message_name = doc.root.name
      message_class = subclasses.fetch(message_name, self)

      signatures = message_class.signatures(doc)

      signatures = signatures.filter do |signature|
        sig_node = signature.signature

        response_node = sig_node.parent

        next false unless response_node && response_node&.name == "Response"

        response_parent_node = response_node&.parent

        next false unless response_parent_node && response_parent_node&.document?

        ref = sig_node.at_xpath(
          "./ds:SignedInfo/ds:Reference",
          Xmldsig::NAMESPACES,
        )

        next false unless ref

        trimmed_ref = String(String(ref["URI"])[1..-1])

        next false unless trimmed_ref.length > 1

        trimmed_ref == String(doc.root["ID"])
      end

      decrypt_errors = []
      plain_doc = message_class.decrypt(doc, options, decrypt_errors)

      signatures = message_class.signatures(plain_doc) if signatures.empty?

      message = message_class.parse(plain_doc, signatures)
      message.errors.concat(decrypt_errors)
      message.errors.each { |e| puts e }
      message
    end

    def self.from_param(encoded, options = {})
      raise "nil SAML response" if encoded.nil?

      begin
        decoded = Base64.decode64(encoded)
        build(decoded, options)
      rescue => e
        raise "Failed to decode SAML response - #{e.message}"
      end
    end

    def self.decode_query(query)
      decoded = Base64.decode64(query)
      Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(decoded)
    end

    def self.from_query(query)
      decoded = decode_query(query)
      build(decoded)
    end

    def self.signatures(doc)
      signatures = doc.xpath("//ds:Signature", Xmldsig::NAMESPACES)
      signatures.reverse.collect do |node|
        Xmldsig::Signature.new(node)
      end || []
    end

    def self.decrypt(doc, options, errors)
      doc
    end

    def self.parse(doc, signatures = nil)
      message = new
      message.document = doc
      message.signatures = signatures
      message
    end

    def initialize(options = {})
      options.each do |k, v|
        ivar = "@#{k}"
        instance_variable_set ivar, v
      end
    end


    def to_param
      Base64.strict_encode64(to_xml)
    end

    def to_query
      deflated = Zlib::Deflate.deflate(to_s, 9)[2..-5]
      Base64.strict_encode64(deflated)
    end

    def ==(other)
      other.document.to_xml == document.to_xml
    end

    def document
      @document ||= build_document
    end
    attr_writer :document

    def signatures
      @signatures ||= []
    end
    attr_writer :signatures

    def errors
      @errors ||= []
    end
    attr_writer :errors

    def sign(options = {})
      unless options[:private_key]
        raise ArgumentError.new("Missing :private_key")
      end

      document.xpath("//ds:Signature", Xmldsig::NAMESPACES).reverse_each do |element|
        signature = Xmldsig::Signature.new(element)

        if options[:certificate]
          encoded_certificate = Base64.strict_encode64(options[:certificate].to_s).chomp

          keyinfo = Nokogiri::XML::Node.new("ds:KeyInfo", document)
          x509Data = Nokogiri::XML::Node.new("ds:X509Data", document)
          x509certificate = Nokogiri::XML::Node.new("ds:X509Certificate", document)

          x509Data << x509certificate
          keyinfo << x509Data
          signature.signature << keyinfo

          signature.signature.at_xpath("descendant::ds:X509Certificate", Xmldsig::NAMESPACES).content = encoded_certificate
        end

        signature.sign(options[:private_key])
      end
    end

    def to_xml(_options = {})
      document.to_xml(save_with: 0)
    end

    def to_s
      to_xml
    end

    def inspect
      to_s
    end

    def valid?(options = {})
      errors.clear
      return false if errors.any?

      validate_schema && validate(options)
      errors.empty?
    end

    private

    def validate(options)
      true
    end

    def build_document
      raise NotImplementedError
    end

    def format_time(t)
      t.to_time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end

    def validate_schema
      Dir.chdir(SCHEMA_DIR) do
        schema = Nokogiri::XML::Schema(File.read("saml20protocol_schema.xsd"))
        self.errors += schema.validate(document)
      end
    end
  end
end
