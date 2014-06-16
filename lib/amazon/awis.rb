require "cgi"
require "base64"
require "openssl"
require "digest/sha1"
require "uri"
require "net/https"
require "time"
require "hpricot"

module Amazon
  class RequestError < StandardError; end

  class Awis
    @@option_defaults = {
      action: "UrlInfo",
      responsegroup: "Rank",
      debug: false
    }

    AWIS_DOMAIN = 'awis.amazonaws.com'

    # Converts a hash into a query string (e.g. {a => 1, b => 2} becomes "a=1&b=2")
    def self.escape_query(query)
      query.to_a.collect { |item| item.first + '=' + CGI::escape(item.last.to_s) }.join('&')
    end

    def self.prepare_url(domain, options)
      params = {
        'AWSAccessKeyId'   => options[:aws_access_key_id],
        'Action'           => options[:action],
        'ResponseGroup'    => options[:responsegroup],
        'SignatureMethod'  => 'HmacSHA1',
        'SignatureVersion' => 2,
        'Timestamp'        => Time.now.utc.iso8601,
        'Url'              => domain
      }

      signature = Base64.encode64(
        OpenSSL::HMAC.digest(
          'sha1', options[:aws_secret_key],
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
      Response.new res.body
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
      def initialize(xml)
        @doc = Hpricot(xml)
      end

      # Return Hpricot object.
      def doc
        @doc
      end

      # Return true if response has an error.
      def has_error?
        !(error.nil? || error.empty?)
      end

      # Return error message.
      def error
        Element.get(@doc, "error/message")
      end

      # Return error code
      def error_code
        Element.get(@doc, "error/code")
      end

      # Return error message.
      def is_success?
        (@doc/"aws:statuscode").innerHTML == "Success"
      end

      #returns inner html of any tag in awis response i.e resp.rank => 3
      def method_missing(methodId)
        txt = (@doc/"aws:#{methodId.id2name}").innerHTML
        if txt.empty?
          raise NoMethodError
        else
          txt
        end
      end
    end
  end

  # Internal wrapper class to provide convenient method to access Hpricot element value.
  class Element
    # Pass Hpricot::Elements object
    def initialize(element)
      @element = element
    end

    # Returns Hpricot::Elments object
    def elem
      @element
    end

    # Find Hpricot::Elements matching the given path. Example: element/"author".
    def /(path)
      elements = @element/path
      return nil if elements.size == 0
      elements
    end

    # Find Hpricot::Elements matching the given path, and convert to Amazon::Element.
    # Returns an array Amazon::Elements if more than Hpricot::Elements size is greater than 1.
    def search_and_convert(path)
      elements = self./(path)
      return unless elements
      elements = elements.map{|element| Element.new(element)}
      return elements.first if elements.size == 1
      elements
    end

    # Get the text value of the given path, leave empty to retrieve current element value.
    def get(path='')
      Element.get(@element, path)
    end

    # Get the unescaped HTML text of the given path.
    def get_unescaped(path='')
      Element.get_unescaped(@element, path)
    end

    # Get the array values of the given path.
    def get_array(path='')
      Element.get_array(@element, path)
    end

    # Get the children element text values in hash format with the element names as the hash keys.
    def get_hash(path='')
      Element.get_hash(@element, path)
    end

    # Similar to #get, except an element object must be passed-in.
    def self.get(element, path='')
      return unless element
      result = element.at(path)
      result = result.inner_html if result
      result
    end

    # Similar to #get_unescaped, except an element object must be passed-in.
    def self.get_unescaped(element, path='')
      result = get(element, path)
      CGI::unescapeHTML(result) if result
    end

    # Similar to #get_array, except an element object must be passed-in.
    def self.get_array(element, path='')
      return unless element

      result = element/path
      if (result.is_a? Hpricot::Elements) || (result.is_a? Array)
        parsed_result = []
        result.each {|item|
        parsed_result << Element.get(item)
        }
        parsed_result
      else
        [Element.get(result)]
      end
    end

    # Similar to #get_hash, except an element object must be passed-in.
    def self.get_hash(element, path='')
      return unless element

        result = element.at(path)
        if result
          hash = {}
          result = result.children
          result.each do |item|
          hash[item.name.to_sym] = item.inner_html
        end

        hash
      end
    end

    def to_s
      elem.to_s if elem
    end
  end
end