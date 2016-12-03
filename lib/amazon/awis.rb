require "cgi"
require "base64"
require "openssl"
require "digest/sha1"
require "uri"
require "net/https"
require "time"
require "nokogiri"

module Amazon
  class RequestError < StandardError; end

  class Awis
    AWIS_DOMAIN = 'awis.amazonaws.com'

    # Converts a hash into a query string (e.g. {a => 1, b => 2} becomes "a=1&b=2")
    def self.escape_query(query)
      query.to_a.sort_by(&:first).map { |item| item.first + '=' + CGI::escape(item.last.to_s) }.join('&')
    end

    def self.prepare_url(domain, action, options)
      timestamp_now = Time.now.utc.iso8601

      params = {
        'AWSAccessKeyId'   => options[:aws_access_key_id],
        'Action'           => action,
        'SignatureMethod'  => 'HmacSHA256',
        'SignatureVersion' => 2,
        'Timestamp'        => timestamp_now,
        'Url'              => domain
      }

      # Set defaults for actions
      case action
      when 'TrafficHistory'
        params['ResponseGroup'] = options[:response_group] || 'History'
        params['Start'] = options[:start] || timestamp_now
      when 'UrlInfo'
        params['ResponseGroup'] = options[:response_group] || 'RankByCountry'
      else
        raise "Unsupported Amazon AWIS action:#{action}"
      end

      signature = Base64.encode64(
        OpenSSL::HMAC.digest(
          'sha256', options[:aws_secret_key],
          "GET\n#{AWIS_DOMAIN}\n/\n" + escape_query(params).strip
        )
      ).chomp

      query = escape_query(
        params.merge('Signature' => signature)
      )

      URI.parse "http://#{AWIS_DOMAIN}/?#{query}"
    end

    def initialize(options)
      @options = options
      @action = options.delete(:action) || 'TrafficHistory'

      @debug = @options[:debug]
    end

    def get_info(domain)
      url = self.class.prepare_url(domain, @action, @options)
      log "Request URL: #{url}"

      # Amazon alexa endpoint seems to have problems and sometimes returns a 404 for valid
      # awis requests - as a workaround, we hammer the endpoint max 20 times until we get
      # a proper response -

      request_counter = 0

      while res = Net::HTTP.get_response(url) do
        request_counter += 1
        break if res.kind_of? Net::HTTPSuccess || request_counter >= 20
      end

      unless res.kind_of? Net::HTTPSuccess
        raise Amazon::RequestError, "HTTP Response: #{res.code} #{res.message} #{res.body}"
      end
      log "Response text: #{res.body}"

      Response.new(res.body, @action)
    end

    def log(s)
      return unless @debug
      if defined? RAILS_DEFAULT_LOGGER
        RAILS_DEFAULT_LOGGER.error s
      elsif defined? LOGGER
        LOGGER.error s
      else
        puts s
      end
    end

    # Response object returned after a REST call to Amazon service.
    class Response
      # XML input is in string format
      def initialize(xml, type)
        @type = type
        @doc = Nokogiri::XML.parse xml
        # make parsing much easier since namespaces are not required here
        @doc.remove_namespaces!
      end

      def doc
        @doc
      end

      # Return true if response has an error.
      def has_error?
        !(error.nil? || error.empty?)
      end

      # Return error message.
      def error
        @doc.xpath('//Response/Errors/Error/Message').map &:inner_text
      end

      # Return error code
      def error_code
        @doc.xpath('//Response/Errors/Error/Code').map &:inner_text
      end

      # Return error message.
      def success?
        @doc.at('StatusCode').inner_text == 'Success'
      end

      def data
        @doc
      end
    end
  end
end
