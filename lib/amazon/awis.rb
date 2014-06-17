require "cgi"
require "base64"
require "openssl"
require "digest/sha1"
require "uri"
require "net/https"
require "time"

module Amazon
  class RequestError < StandardError; end

  class Awis
    @@option_defaults = {
      action: 'TrafficHistory',
      responsegroup: 'History',
      debug: false
    }

    AWIS_DOMAIN = 'awis.amazonaws.com'

    # Converts a hash into a query string (e.g. {a => 1, b => 2} becomes "a=1&b=2")
    def self.escape_query(query)
      query.to_a.collect { |item| item.first + '=' + CGI::escape(item.last.to_s) }.join('&')
    end

    def self.prepare_url(domain, options)
      timestamp_now = Time.now.utc.iso8601
      params = {
        'AWSAccessKeyId'   => options[:aws_access_key_id],
        'Action'           => options[:action],
        'ResponseGroup'    => options[:responsegroup],
        'SignatureMethod'  => 'HmacSHA256',
        'SignatureVersion' => 2,
        'Start'            => options[:start] || timestamp_now,
        'Timestamp'        => timestamp_now,
        'Url'              => domain
      }

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
      @options = @@option_defaults.merge options
      @debug = @options[:debug]
    end

    def get_info(domain)
      url = self.class.prepare_url(domain, @options)
      log "Request URL: #{url}"
      res = Net::HTTP.get_response url
      unless res.kind_of? Net::HTTPSuccess
        raise Amazon::RequestError, "HTTP Response: #{res.code} #{res.message} #{res.body}"
      end
      log "Response text: #{res.body}"

      Response.new(res.body, @options[:action])
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
        case @type
        when 'TrafficHistory'
          parse_history @doc.at('//TrafficHistory')
        else
          raise "Action type: #{@type} not yet supported"
        end
      end

      def parse_history(node)
        return unless node

        range = node.at('Range').text
        site = node.at('Site').text

        # parse data rows
        row_nodes = node.xpath '//HistoricalData/Data'
        rows = row_nodes.map do |row_node|
          date = row_node.at('Date').text
          rank = row_node.at('Rank').text
          pageviews = row_node.at('PageViews/PerMillion').text
          pageviews_per_user = row_node.at('PageViews/PerUser').text

          reach = row_node.at('Reach/PerMillion').text

          {
            date: date,
            rank: rank,
            pageviews: pageviews,
            pageviews_per_user: pageviews_per_user,
            reach: reach
          }
        end

        {
          range: range,
          site: site,
          rows: rows
        }
      end
    end
  end
end
