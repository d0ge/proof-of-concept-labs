# typed: false
# frozen_string_literal: true

require "forwardable"
require "xmldsig"

module SAML
  class Message
    class AssertionDecryptionHelper

      class EncryptedAssertionError < StandardError
      end

      def initialize(options, errors = nil)
        @key = options[:key]
        @errors = errors

        @namespaces = {
          "ds"   => "http://www.w3.org/2000/09/xmldsig#",
          "xenc" => "http://www.w3.org/2001/04/xmlenc#",
        }

        # Maps the algorithm names from XMLENC to the corresponding OpenSSL
        # algorithm name and block size
        @xmlenc2algo = {
          "#{@namespaces["xenc"]}aes128-cbc"     => { name: "aes-128-cbc", key_size: 128 },
          "#{@namespaces["xenc"]}aes192-cbc"     => { name: "aes-192-cbc", key_size: 192 },
          "#{@namespaces["xenc"]}aes256-cbc"     => { name: "aes-256-cbc", key_size: 256 },
          "#{@namespaces["xenc"]}rsa-oaep-mgf1p" => { name: "rsa-oaep"   , padding: OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING },
        }

        @key_transport_method = options[:key_transport_method]
        if @xmlenc2algo.key?(@key_transport_method)
          @key_transport_method = @xmlenc2algo[@key_transport_method][:name]
        end

        @encryption_method = options[:encryption_method]
        if @xmlenc2algo.key?(@encryption_method)
          @encryption_method = @xmlenc2algo[@encryption_method][:name]
        end

      end

      def errors
        @errors ||= []
      end
      attr_writer :errors

      def decrypt(node)
        return if node.nil?
        decrypted_assertion = decrypt_assertion(node)
        node.replace(decrypted_assertion)
      rescue EncryptedAssertionError => e
        self.errors << "SAML #{e}"
      rescue OpenSSL::PKey::RSAError => e
        self.errors << "Unable to decrypt SAML assertions. Is the IDP using the wrong certificate?"
      end

      def remove_padding(data, block_size)
        padding = data[-1].bytes[0]
        if padding < 1
          raise EncryptedAssertionError.new "expected padding greater than 0 but got #{padding}"
        elsif padding > block_size
          raise EncryptedAssertionError.new "expected padding smaller than #{block_size} but got #{padding}"
        end
        data[0...-padding]
      end

      private

      def algorithm(enc_assert_node)
        xmlenc_algo = enc_assert_node.at_xpath("./xenc:EncryptionMethod/@Algorithm", @namespaces).value
        @xmlenc2algo.fetch(xmlenc_algo, { name: "unknown" })
      end

      def cipher_key(node)
        enc_key_node = node.at_xpath("./xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey", @namespaces)
        if !enc_key_node
          cipher_uri    = node.at_xpath("./xenc:EncryptedData/ds:KeyInfo/ds:RetrievalMethod/@URI", @namespaces).value.delete_prefix("#")
          enc_key_node  = node.at_xpath("./xenc:EncryptedKey[@Id='#{cipher_uri}']", @namespaces)
        end

        key_transport = algorithm(enc_key_node)
        if key_transport[:name] != @key_transport_method
          raise EncryptedAssertionError.new "expected #{@key_transport_method.upcase} as key transport method for encrypted assertions but got #{key_transport[:name].upcase}"
        end

        cipher_base64 = enc_key_node.at_xpath("./xenc:CipherData/xenc:CipherValue", @namespaces).text
        cipher        = Base64.decode64(cipher_base64)

        raise EncryptedAssertionError.new "is missing private key" if @key.nil?
        @key.private_decrypt(cipher, key_transport[:padding])
      end

      def data(node)
        data_base64 = node.at_xpath("./xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", @namespaces).text
        Base64.decode64(data_base64)
      end

      def decrypt_assertion(node)
        encryption = algorithm(node.at_xpath("./xenc:EncryptedData", @namespaces))
        if encryption[:name] != @encryption_method
          raise EncryptedAssertionError.new "expected #{@encryption_method.upcase} as algorithm for encrypted assertions but got #{encryption[:name].upcase}"
        end

        key  = cipher_key(node)
        data = data(node)

        iv = data[0..15]
        cipher_text = data[16..-1]

        decipher = OpenSSL::Cipher.new(encryption[:name])
        decipher.decrypt
        decipher.padding = 0
        decipher.key = key
        decipher.iv = iv

        plain_data = decipher.update(cipher_text) + decipher.final
        remove_padding(plain_data, decipher.block_size)
      end

    end

    class Response < Message
      include Scientist
      include SAML::Shared::Issuer
      include SAML::Shared::Status
      include SAML::Shared::Response

      attr_accessor :name_id             
      attr_accessor :name_id_format      
      attr_accessor :subject             
      attr_accessor :session_expires_at  
      attr_accessor :session_index      
      attr_accessor :status_message

      def self.decrypt(doc, options, errors)
        return doc unless options && !!options[:encrypted_assertions]

        dup_doc = doc.dup
        node = dup_doc.at_xpath("/saml2p:Response/saml2:EncryptedAssertion", namespaces)
        if node
          AssertionDecryptionHelper.new(options, errors).decrypt(node)
        else
          errors << "Expected SAML encrypted assertions but none found"
          dup_doc.xpath("/saml2p:Response/saml2:Assertion", namespaces).each do |assertion|
            assertion.remove
          end
        end
        dup_doc
      end

      def self.parse(doc, signatures = nil)
        d = doc.dup

        sig_nodes = d.xpath("//ds:Signature", namespaces)

        if sig_nodes && !sig_nodes.empty?
          sig_nodes.each do |sig_node|
            sig_node.remove
          end
        end

        destination = d.root.attr("Destination")

        issuer = d.at_xpath("/saml2p:Response/saml2:Issuer", namespaces) && d.at_xpath("/saml2p:Response/saml2:Issuer", namespaces).text
        issuer ||= d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Issuer", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Issuer", namespaces).text

        status_code = d.at_xpath("/saml2p:Response/saml2p:Status/saml2p:StatusCode", namespaces)
        status_code = status_code && status_code.attr("Value")

        second_level_status_code = d.at_xpath("/saml2p:Response/saml2p:Status/saml2p:StatusCode/saml2p:StatusCode", namespaces)
        second_level_status_code = second_level_status_code && second_level_status_code.attr("Value")

        status_message = d.at_xpath("/saml2p:Response/saml2p:Status/saml2p:StatusMessage", namespaces)
        status_message = status_message && status_message.text

        authn = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:AuthnStatement", namespaces)

        expiry = authn && authn["SessionNotOnOrAfter"]
        expiry = expiry && Time.parse(expiry + " UTC")

        session_index = authn && authn["SessionIndex"]

        conditions = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Conditions", namespaces)
        not_before = conditions && conditions["NotBefore"]
        not_before = not_before && Time.parse(not_before + " UTC")
        not_on_or_after = conditions && conditions["NotOnOrAfter"]
        not_on_or_after = not_on_or_after && Time.parse(not_on_or_after + " UTC")
        audience_text = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Conditions/saml2:AudienceRestriction", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Conditions/saml2:AudienceRestriction/saml2:Audience", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Conditions/saml2:AudienceRestriction/saml2:Audience", namespaces).text

        attribute_statements = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:AttributeStatement", namespaces)
        attributes = attribute_statements && attribute_statements.xpath("saml2:Attribute", namespaces).inject({}) do |attrs, attribute|

          name = attribute["Name"]
          friendly_name = attribute["FriendlyName"]
          values = attribute.xpath("saml2:AttributeValue", namespaces).map do |attribute_value|
            attribute_value.text
          end
          attrs[name] = attrs[name.to_sym] = values
          if friendly_name
            attrs[friendly_name] = attrs[friendly_name.to_sym] = values
          end
          attrs
        end

        subject = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject", namespaces).text
        name_id = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID", namespaces).text
        name_id_format = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID", namespaces)["Format"]

        subj_conf_data = d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:SubjectConfirmation", namespaces) && d.at_xpath("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:SubjectConfirmation/saml2:SubjectConfirmationData", namespaces)
        recipient_attr = subj_conf_data && subj_conf_data["Recipient"]
        in_response_to_attr = subj_conf_data && subj_conf_data["InResponseTo"]

        errors = []

        if in_response_to_attr && d.root.attr("InResponseTo") && d.root.attr("InResponseTo") != in_response_to_attr
          errors << "InResponseTo value on the Response element doesn't match the InResponseTo value in the SubjectConfirmationData element."
        end

        new({
          destination: destination,
          name_id: name_id,
          name_id_format: name_id_format || "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
          subject: subject,
          issuer: issuer,
          in_response_to: in_response_to_attr || d.root.attr("InResponseTo"),
          recipient: recipient_attr,
          audience: audience_text,
          session_expires_at: expiry,
          session_index: session_index,
          status_code: status_code,
          second_level_status_code: second_level_status_code,
          status_message: status_message,
          not_before: not_before,
          not_on_or_after: not_on_or_after,
          attributes: attributes,
          document: doc,
          signatures: signatures,
          errors: errors,
        })
      end

      def build_document(include_sig_template: false)
        return @document if @document

        doc = Nokogiri::XML::Builder.new do |xml|
          root_attributes = {
            "xmlns:samlp"     => "urn:oasis:names:tc:SAML:2.0:protocol",
            "xmlns:saml"      => "urn:oasis:names:tc:SAML:2.0:assertion",
            "xmlns:ds"        =>  "http://www.w3.org/2000/09/xmldsig#",
            "ID"              => id,
            "IssueInstant"    => format_time(issue_instant),
            "Version"         => version,
          }
          root_attributes["Destination"]  = destination    if destination.present?
          root_attributes["InResponseTo"] = in_response_to if in_response_to.present?

          xml.Response(root_attributes) do
            xml.parent.namespace = xml.parent.namespace_definitions.first

            generate_issuer(xml)

            xml_signature_template(xml, id) if include_sig_template

            generate_status(xml)

            if @attributes 
              assertion = Assertion.new({
                attributes: @attributes,
                issuer: issuer,
                name_id: name_id,
                name_id_format: name_id_format,
                recipient: recipient,
                audience: audience,
              })
              assertion.decorate(xml)
            end
          end
        end.doc

        @document = doc
        @document
      end

      def xml_signature_template(builder, uri)
        builder["ds"].Signature do |builder|
          builder.SignedInfo do |builder|
            builder.CanonicalizationMethod(Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#")
            builder.SignatureMethod(Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            builder.Reference(URI: "#" + String(uri)) do |builder|
              builder.Transforms do |builder|
                builder.Transform(Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
                builder.Transform(Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#")
              end
              builder.DigestMethod(Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256")
              builder.DigestValue
            end
          end
          builder.SignatureValue
        end
      end

      def validate(options)

        validate_has_signature
        validate_certificate(options[:idp_certificate]) if certificate_expiration_check_enabled?
        # main logic starts here  
        validate_assertion_digest_values

        if self.saml_encrypted_assertions?
          validate_signatures_ghes(options[:idp_certificate])
        else
          validate_signatures(options[:idp_certificate])
        end

        return if self.errors.any?
        validate_has_assertion
        validate_issuer(options[:issuer])
        validate_destination(options[:sp_url],options[:dst_url])
        validate_recipient(options[:sp_url],options[:dst_url])

        validate_audience(audience_url(options[:sp_url]))
        validate_name_id_format(options[:name_id_format])

        has_multiple_assertions = document.xpath("//saml2:Assertion", namespaces).count > 1
        has_errors = !self.errors.empty?
        has_root_sig = has_root_sig_and_matching_ref?

      end

      def validate_issuer(expected)
        return if !expected || expected.empty?
        if String(issuer) != expected
          self.errors << "Issuer is invalid."
        end
      end

      def validate_audience(sp_url)
        error = audience_validation(sp_url)
        if error
          self.errors << error
        end
      end

      def dump_xml_without_signature
        doc_copy = self.document.dup
        if sig = doc_copy.xpath("//ds:Signature", namespaces)
          sig.remove
        end
        doc_copy.to_xml(indent: 2)
      end

      def audience_validation(sp_url)
        if !audience || audience.downcase != sp_url&.downcase
          "Audience is invalid. Audience attribute does not match #{sp_url}"
        end
      end

      def validate_name_id_format(specified_format)
        return unless specified_format

        if name_id_format && name_id_format != specified_format
          self.errors << "NameID format must be '#{ specified_format }'."
          nil
        end
      end


      def validate_recipient(sp_url, dst_url)
        return if !subject
        if !recipient
          self.errors << "Recipient in the SAML response must not be blank."
          return
        end
        if recipient.downcase != "#{dst_url&.downcase}"
          self.errors << "Recipient in the SAML response was not valid."
          nil
        end
      end

      def validate_destination(sp_url, dst_url)
        # destination is only required when the message is signed, not the assertion
        return unless has_root_sig_and_matching_ref?
        # unless destination && destination.downcase == "#{sp_url&.downcase}/saml/consume"
        unless destination && destination.downcase == "#{dst_url&.downcase}"
          self.errors << "Destination in the SAML response was not valid."
          nil
        end
      end

      def validate_has_signature
        return if has_root_sig_and_matching_ref?
        return if all_assertions_signed_with_matching_ref?

        self.errors << "SAML Response is not signed or has been modified."
      end

      def validate_signatures(raw_cert)
        unless raw_cert
          self.errors << "No Certificate"
          return
        end
        certificate = OpenSSL::X509::Certificate.new(raw_cert)
        unless signatures.all? { |signature| signature.valid?(certificate) }
          self.errors << "Digest mismatch"
        end
      rescue Xmldsig::SchemaError => e
        self.errors << "Invalid signature"
      rescue OpenSSL::X509::CertificateError => e
        self.errors << "Certificate error: '#{e.message}'"
      end

      def validate_signatures_ghes(raw_cert)
        unless raw_cert
          self.errors << "No Certificate"
          return
        end

        unless signatures.any?
          self.errors << "No signatures found"
          return
        end

        certificate = OpenSSL::X509::Certificate.new(raw_cert)
        unless signatures.all? { |signature| signature.valid?(certificate) }
          self.errors << "Digest mismatch"
        end
      rescue Xmldsig::SchemaError => e
        self.errors << "Invalid signature"
      rescue OpenSSL::X509::CertificateError => e
        self.errors << "Certificate error: '#{e.message}'"
      end

      def certificate_expiration_check_enabled?
        false
      end

      def validate_certificate(raw_cert)
        certificate = OpenSSL::X509::Certificate.new(raw_cert)
        expired_at = certificate.not_after
        if expired_at.to_i <= Time.now.to_i
          self.errors << "IdP signing certificate expired"
        end
      end

      def validate_has_assertion
        return if !document.at("/saml2p:Response/saml2:Assertion", namespaces).nil?
        self.errors << "No assertion found"
      end

      def has_root_sig_and_matching_ref?
        root_ref = document.at("/saml2p:Response/ds:Signature/ds:SignedInfo/ds:Reference", namespaces)
        return false unless root_ref
        root_ref_uri = String(String(root_ref["URI"])[1..-1]) 
        return false unless root_ref_uri.length > 1
        root_rep = document.at("/saml2p:Response", namespaces)
        root_id = String(root_rep["ID"])

        root_ref_uri == root_id
      end

      def all_assertions_signed_with_matching_ref?
        assertions = document.xpath("//saml2:Assertion", namespaces)
        assertions.all? do |assertion|
          ref = assertion.at("./ds:Signature/ds:SignedInfo/ds:Reference", namespaces)
          return false unless ref
          assertion_id = String(assertion["ID"])
          ref_uri = String(String(ref["URI"])[1..-1]) 
          return false unless ref_uri.length > 1

          ref_uri == assertion_id
        end
      end


      def validate_assertion_digest_values
        return if all_assertion_digests_valid?

        self.errors << "SAML Response has been modified."
      end

      def all_assertion_digests_valid?
        return true if has_root_sig_and_matching_ref?

        assertions = document.dup.xpath("//saml2:Assertion", namespaces)

        assertions.all? do |assertion|
          signature_ref = assertion.at("./ds:Signature/ds:SignedInfo/ds:Reference", namespaces)
          return false unless signature_ref
          assertion_id = String(assertion["ID"])
          ref_uri = String(String(signature_ref["URI"])[1..-1]) 
          return false unless ref_uri.length > 1
          return false unless assertion_id == ref_uri

          xml_signature_ref = Xmldsig::Reference.new(signature_ref)

          actual_digest = xml_signature_ref.digest_value
          calculated_digest = calculate_assertion_digest(assertion, xml_signature_ref)

          digest_valid = calculated_digest == actual_digest

          puts "Running all_assertion_digests_valid?"
          puts "saml.signature.digest_valid: #{digest_valid}"
          puts "saml.signature.calculated_digest: #{Base64.encode64(calculated_digest)}"
          puts "saml.signature.actual_digest: #{Base64.encode64(actual_digest)}"
          puts "saml.signature.assertion: #{Base64.encode64(assertion&.to_s)}"
          puts "saml.signatures.count: #{signatures&.count}"
          puts "saml.assertions.count: #{assertions&.count}"

          digest_valid
        end
      end

      def calculate_assertion_digest(assertion, xml_signature_ref)
        transformed = xml_signature_ref.transforms.apply(assertion)
        case transformed
        when String
          xml_signature_ref.digest_method.digest transformed
        when Nokogiri::XML::Node
          xml_signature_ref.digest_method.digest Xmldsig::Canonicalizer.new(transformed).canonicalize
        end
      end

      def self.namespaces
        {
          "ds" => "http://www.w3.org/2000/09/xmldsig#",
          "saml2p" => "urn:oasis:names:tc:SAML:2.0:protocol",
          "saml2" => "urn:oasis:names:tc:SAML:2.0:assertion",
        }
      end

      def namespaces
        self.class.namespaces
      end


      def audience_url(sp_url)
        sp_url
      end

    end
  end
end
