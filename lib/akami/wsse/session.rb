require 'akami/wsse/certs'

module Akami
  class WSSE
    class Session

      attr_accessor :certs

      def initialize(certs = Certs.new)
        @certs = certs
      end

      def namespace
        :xenc
      end

      def tag
        'EncryptedKey'
      end

      def hash
        {
          'xenc:EncryptionMethod' => '',
          'ds:KeyInfo' => {
            'wsse:SecurityTokenReference' => {
              'wsse:KeyIdentifier' => sha1_thumbprint,
              :attributes! => {
                'wsse:KeyIdentifier' => {
                  'EncodingType' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary',
                  'ValueType'    => 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1'
                }
              }
            }
          },
          'xenc:CipherData' => {
            'xenc:CipherValue' => encrypted_key
          },
          :attributes! => {
            'xenc:EncryptionMethod' => {
              'Algorithm' => 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
            },
            'ds:KeyInfo' =>  {
              'xmlns:ds' => "http://www.w3.org/2000/09/xmldsig#"
            }
          }
        }
      end

      def extra
        {
          :attributes! => {
            'xenc:EncryptedKey' => {
              'xmlns:xenc' => 'http://www.w3.org/2001/04/xmlenc#',
              'Id'         => "EK-#{uid}"
            }
          }
        }
      end

    private

      def sha1_thumbprint
        Base64.strict_encode64(OpenSSL::Digest::SHA1.digest(certs.cert.to_der))
      end

      def encrypted_key
        encrypt(random_string)
      end

      def encrypt(string)
        padding = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
        encrypted = certs.cert.public_key.public_encrypt(string, padding)
        Base64.strict_encode64(encrypted)
      end

      def encode(element)
        Base64.encode64(element).gsub("\n", '')
      end

      def uid
        OpenSSL::Digest::SHA1.hexdigest(
          [Time.now, rand].collect(&:to_s).join('/')
        )
      end

      def random_string
        (0...100).map { ("a".."z").to_a[rand(26)] }.join
      end

    end
  end
end
