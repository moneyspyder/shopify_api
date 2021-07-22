# frozen_string_literal: true
require 'shopify_api/version'

# https://github.com/rails/activeresource/blob/b80b4fbe3d44fd788c92d5286244dc09a2a12c4b/lib/active_resource/base.rb


module ActiveResource
  class Base

    ##
    # :singleton-method:
    # The logger for diagnosing and tracing Active Resource calls.
    cattr_reader :logger

    def self.logger=(logger)
      self._connection = nil
      @@logger = logger
    end

    class_attribute :_format
    class_attribute :_collection_parser
    class_attribute :include_format_in_path
    self.include_format_in_path = true

    class_attribute :connection_class
    self.connection_class = Connection    

    class_attribute :_collection_parser    

    class << self      

     include ThreadsafeAttributes
      threadsafe_attribute :_headers, :_connection, :_user, :_password, :_bearer_token, :_site, :_proxy

      # Creates a schema for this resource - setting the attributes that are
      # known prior to fetching an instance from the remote system.
      #
      # The schema helps define the set of <tt>known_attributes</tt> of the
      # current resource.
      #
      # There is no need to specify a schema for your Active Resource. If
      # you do not, the <tt>known_attributes</tt> will be guessed from the
      # instance attributes returned when an instance is fetched from the
      # remote system.
      #
      # example:
      #   class Person < ActiveResource::Base
      #     schema do
      #       # define each attribute separately
      #       attribute 'name', :string
      #
      #       # or use the convenience methods and pass >=1 attribute names
      #       string  'eye_color', 'hair_color'
      #       integer 'age'
      #       float   'height', 'weight'
      #
      #       # unsupported types should be left as strings
      #       # overload the accessor methods if you need to convert them
      #       attribute 'created_at', 'string'
      #     end
      #   end
      #
      #   p = Person.new
      #   p.respond_to? :name   # => true
      #   p.respond_to? :age    # => true
      #   p.name                # => nil
      #   p.age                 # => nil
      #
      #   j = Person.find_by_name('John')
      #   <person><name>John</name><age>34</age><num_children>3</num_children></person>
      #   j.respond_to? :name   # => true
      #   j.respond_to? :age    # => true
      #   j.name                # => 'John'
      #   j.age                 # => '34'  # note this is a string!
      #   j.num_children        # => '3'  # note this is a string!
      #
      #   p.num_children        # => NoMethodError
      #
      # Attribute-types must be one of: <tt>string, text, integer, float, decimal, datetime, timestamp, time, date, binary, boolean</tt>
      #
      # Note: at present the attribute-type doesn't do anything, but stay
      # tuned...
      # Shortly it will also *cast* the value of the returned attribute.
      # ie:
      # j.age                 # => 34   # cast to an integer
      # j.weight              # => '65' # still a string!
      #
      def schema(&block)
        if block_given?
          schema_definition = Schema.new
          schema_definition.instance_eval(&block)

          # skip out if we didn't define anything
          return unless schema_definition.attrs.present?

          @schema ||= {}.with_indifferent_access
          @known_attributes ||= []

          schema_definition.attrs.each do |k, v|
            @schema[k] = v
            @known_attributes << k
          end

          @schema
        else
          @schema ||= nil
        end
      end

      # Alternative, direct way to specify a <tt>schema</tt> for this
      # Resource. <tt>schema</tt> is more flexible, but this is quick
      # for a very simple schema.
      #
      # Pass the schema as a hash with the keys being the attribute-names
      # and the value being one of the accepted attribute types (as defined
      # in <tt>schema</tt>)
      #
      # example:
      #
      #   class Person < ActiveResource::Base
      #     self.schema = {'name' => :string, 'age' => :integer }
      #   end
      #
      # The keys/values can be strings or symbols. They will be converted to
      # strings.
      #
      def schema=(the_schema)
        unless the_schema.present?
          # purposefully nulling out the schema
          @schema = nil
          @known_attributes = []
          return
        end

        raise ArgumentError, "Expected a hash" unless the_schema.kind_of? Hash

        schema do
          the_schema.each { |k, v| attribute(k, v) }
        end
      end

      # Returns the list of known attributes for this resource, gathered
      # from the provided <tt>schema</tt>
      # Attributes that are known will cause your resource to return 'true'
      # when <tt>respond_to?</tt> is called on them. A known attribute will
      # return nil if not set (rather than <tt>MethodNotFound</tt>); thus
      # known attributes can be used with <tt>validates_presence_of</tt>
      # without a getter-method.
      def known_attributes
        @known_attributes ||= []
      end

      # Gets the URI of the REST resources to map for this class. The site variable is required for
      # Active Resource's mapping to work.
      def site
        # Not using superclass_delegating_reader because don't want subclasses to modify superclass instance
        #
        # With superclass_delegating_reader
        #
        #   Parent.site = 'https://anonymous@test.com'
        #   Subclass.site # => 'https://anonymous@test.com'
        #   Subclass.site.user = 'david'
        #   Parent.site # => 'https://david@test.com'
        #
        # Without superclass_delegating_reader (expected behavior)
        #
        #   Parent.site = 'https://anonymous@test.com'
        #   Subclass.site # => 'https://anonymous@test.com'
        #   Subclass.site.user = 'david' # => TypeError: can't modify frozen object
        #
        if _site_defined?
          _site
        elsif superclass != Object && superclass.site
          superclass.site.dup.freeze
        end
      end

      # Sets the URI of the REST resources to map for this class to the value in the +site+ argument.
      # The site variable is required for Active Resource's mapping to work.
      def site=(site)
        self._connection = nil
        if site.nil?
          self._site = nil
        else
          self._site = create_site_uri_from(site)
          self._user = URI::DEFAULT_PARSER.unescape(_site.user) if _site.user
          self._password = URI::DEFAULT_PARSER.unescape(_site.password) if _site.password
        end
      end

      # Gets the \proxy variable if a proxy is required
      def proxy
        # Not using superclass_delegating_reader. See +site+ for explanation
        if _proxy_defined?
          _proxy
        elsif superclass != Object && superclass.proxy
          superclass.proxy.dup.freeze
        end
      end

      # Sets the URI of the http proxy to the value in the +proxy+ argument.
      def proxy=(proxy)
        self._connection = nil
        self._proxy = proxy.nil? ? nil : create_proxy_uri_from(proxy)
      end

      # Gets the \user for REST HTTP authentication.
      def user
        # Not using superclass_delegating_reader. See +site+ for explanation
        if _user_defined?
          _user
        elsif superclass != Object && superclass.user
          superclass.user.dup.freeze
        end
      end

      # Sets the \user for REST HTTP authentication.
      def user=(user)
        self._connection = nil
        self._user = user
      end

      # Gets the \password for REST HTTP authentication.
      def password
        # Not using superclass_delegating_reader. See +site+ for explanation
        if _password_defined?
          _password
        elsif superclass != Object && superclass.password
          superclass.password.dup.freeze
        end
      end

      # Sets the \password for REST HTTP authentication.
      def password=(password)
        self._connection = nil
        self._password = password
      end

      # Gets the \bearer_token for REST HTTP authentication.
      def bearer_token
        # Not using superclass_delegating_reader. See +site+ for explanation
        if _bearer_token_defined?
          _bearer_token
        elsif superclass != Object && superclass.bearer_token
          superclass.bearer_token.dup.freeze
        end
      end

      # Sets the \bearer_token for REST HTTP authentication.
      def bearer_token=(bearer_token)
        self._connection = nil
        self._bearer_token = bearer_token
      end

      def auth_type
        if defined?(@auth_type)
          @auth_type
        end
      end

      def auth_type=(auth_type)
        self._connection = nil
        @auth_type = auth_type
      end

      # Sets the format that attributes are sent and received in from a mime type reference:
      #
      #   Person.format = :json
      #   Person.find(1) # => GET /people/1.json
      #
      #   Person.format = ActiveResource::Formats::XmlFormat
      #   Person.find(1) # => GET /people/1.xml
      #
      # Default format is <tt>:json</tt>.
      def format=(mime_type_reference_or_format)
        format = mime_type_reference_or_format.is_a?(Symbol) ?
          ActiveResource::Formats[mime_type_reference_or_format] : mime_type_reference_or_format

        self._format = format
        connection.format = format if site
      end

      # Returns the current format, default is ActiveResource::Formats::JsonFormat.
      def format
        self._format || ActiveResource::Formats::JsonFormat
      end

      # Sets the parser to use when a collection is returned.  The parser must be Enumerable.
      def collection_parser=(parser_instance)
        parser_instance = parser_instance.constantize if parser_instance.is_a?(String)
        self._collection_parser = parser_instance
      end

      def collection_parser
        self._collection_parser || ActiveResource::Collection
      end

      # Sets the number of seconds after which requests to the REST API should time out.
      def timeout=(timeout)
        self._connection = nil
        @timeout = timeout
      end

      # Sets the number of seconds after which connection attempts to the REST API should time out.
      def open_timeout=(timeout)
        self._connection = nil
        @open_timeout = timeout
      end

      # Sets the number of seconds after which reads to the REST API should time out.
      def read_timeout=(timeout)
        self._connection = nil
        @read_timeout = timeout
      end

      # Gets the number of seconds after which requests to the REST API should time out.
      def timeout
        if defined?(@timeout)
          @timeout
        elsif superclass != Object && superclass.timeout
          superclass.timeout
        end
      end

      # Gets the number of seconds after which connection attempts to the REST API should time out.
      def open_timeout
        if defined?(@open_timeout)
          @open_timeout
        elsif superclass != Object && superclass.open_timeout
          superclass.open_timeout
        end
      end

      # Gets the number of seconds after which reads to the REST API should time out.
      def read_timeout
        if defined?(@read_timeout)
          @read_timeout
        elsif superclass != Object && superclass.read_timeout
          superclass.read_timeout
        end
      end

      # Options that will get applied to an SSL connection.
      #
      # * <tt>:key</tt> - An OpenSSL::PKey::RSA or OpenSSL::PKey::DSA object.
      # * <tt>:cert</tt> - An OpenSSL::X509::Certificate object as client certificate
      # * <tt>:ca_file</tt> - Path to a CA certification file in PEM format. The file can contain several CA certificates.
      # * <tt>:ca_path</tt> - Path of a CA certification directory containing certifications in PEM format.
      # * <tt>:verify_mode</tt> - Flags for server the certification verification at beginning of SSL/TLS session. (OpenSSL::SSL::VERIFY_NONE or OpenSSL::SSL::VERIFY_PEER is acceptable)
      # * <tt>:verify_callback</tt> - The verify callback for the server certification verification.
      # * <tt>:verify_depth</tt> - The maximum depth for the certificate chain verification.
      # * <tt>:cert_store</tt> - OpenSSL::X509::Store to verify peer certificate.
      # * <tt>:ssl_timeout</tt> -The SSL timeout in seconds.
      def ssl_options=(options)
        self._connection = nil
        @ssl_options = options
      end

      # Returns the SSL options hash.
      def ssl_options
        if defined?(@ssl_options)
          @ssl_options
        elsif superclass != Object && superclass.ssl_options
          superclass.ssl_options
        end
      end

      # An instance of ActiveResource::Connection that is the base \connection to the remote service.
      # The +refresh+ parameter toggles whether or not the \connection is refreshed at every request
      # or not (defaults to <tt>false</tt>).
      def connection(refresh = false)
        if _connection_defined? || superclass == Object
          self._connection = connection_class.new(
            site, format
          ) if refresh || _connection.nil?
          _connection.proxy = proxy if proxy
          _connection.user = user if user
          _connection.password = password if password
          _connection.bearer_token = bearer_token if bearer_token
          _connection.auth_type = auth_type if auth_type
          _connection.timeout = timeout if timeout
          _connection.open_timeout = open_timeout if open_timeout
          _connection.read_timeout = read_timeout if read_timeout
          _connection.ssl_options = ssl_options if ssl_options
          _connection
        else
          superclass.connection
        end
      end

      def headers
        headers_state = self._headers || {}
        if superclass != Object
          self._headers = superclass.headers.merge(headers_state)
        else
          headers_state
        end
      end

      attr_writer :element_name

      def element_name
        @element_name ||= model_name.element
      end

      attr_writer :collection_name

      def collection_name
        @collection_name ||= ActiveSupport::Inflector.pluralize(element_name)
      end

      attr_writer :primary_key

      def primary_key
        if defined?(@primary_key)
          @primary_key
        elsif superclass != Object && superclass.primary_key
          primary_key = superclass.primary_key
          return primary_key if primary_key.is_a?(Symbol)
          primary_key.dup.freeze
        else
          "id"
        end
      end

      # Gets the \prefix for a resource's nested URL (e.g., <tt>prefix/collectionname/1.json</tt>)
      # This method is regenerated at runtime based on what the \prefix is set to.
      def prefix(options = {})
        default = site.path
        default << "/" unless default[-1..-1] == "/"
        # generate the actual method based on the current site path
        self.prefix = default
        prefix(options)
      end

      # An attribute reader for the source string for the resource path \prefix. This
      # method is regenerated at runtime based on what the \prefix is set to.
      def prefix_source
        prefix # generate #prefix and #prefix_source methods first
        prefix_source
      end

      # Sets the \prefix for a resource's nested URL (e.g., <tt>prefix/collectionname/1.json</tt>).
      # Default value is <tt>site.path</tt>.
      def prefix=(value = "/")
        # Replace :placeholders with '#{embedded options[:lookups]}'
        prefix_call = value.gsub(/:\w+/) { |key| "\#{URI::DEFAULT_PARSER.escape options[#{key}].to_s}" }

        # Clear prefix parameters in case they have been cached
        @prefix_parameters = nil

        silence_warnings do
          # Redefine the new methods.
          instance_eval <<-RUBY_EVAL, __FILE__, __LINE__ + 1
            def prefix_source() "#{value}" end
            def prefix(options={}) "#{prefix_call}" end
          RUBY_EVAL
        end
      rescue Exception => e
        logger.error "Couldn't set prefix: #{e}\n  #{code}" if logger
        raise
      end

      alias_method :set_prefix, :prefix=  #:nodoc:

      alias_method :set_element_name, :element_name=  #:nodoc:
      alias_method :set_collection_name, :collection_name=  #:nodoc:

      def format_extension
        include_format_in_path ? ".#{format.extension}" : ""
      end
      
      # Sets the parser to use when a collection is returned.  The parser must be Enumerable.
      def collection_parser=(parser_instance)
        parser_instance = parser_instance.constantize if parser_instance.is_a?(String)
        self._collection_parser = parser_instance
      end

      def collection_parser
        self._collection_parser || ActiveResource::Collection
      end

    end

  end
end

module ShopifyAPI
  class Base < ActiveResource::Base
    class InvalidSessionError < StandardError; end
    extend Countable

    self.timeout = 90
    self.include_root_in_json = false
    self.headers['User-Agent'] = ["ShopifyAPI/#{ShopifyAPI::VERSION}",
                                  "ActiveResource/#{ActiveResource::VERSION::STRING}",
                                  "Ruby/#{RUBY_VERSION}"].join(' ')

    self.collection_parser = ShopifyAPI::PaginatedCollection

    def encode(options = {})
      same = dup
      same.attributes = { self.class.element_name => same.attributes } if self.class.format.extension == 'json'

      same.send("to_#{self.class.format.extension}", options)
    end

    def as_json(options = nil)
      root = options[:root] if options.try(:key?, :root)
      if include_root_in_json
        root = self.class.model_name.element if root == true
        { root => serializable_hash(options) }
      else
        serializable_hash(options)
      end
    end

    class << self
      threadsafe_attribute(:_api_version)
      def headers
        if _headers_defined?
          _headers
        elsif superclass != Object && superclass.headers
          superclass.headers
        else
          _headers ||= {}
        end
      end

      def activate_session(session)
        raise InvalidSessionError, "Session cannot be nil" if session.nil?
        self.site = session.site
        self.headers.merge!('X-Shopify-Access-Token' => session.token)
        self.api_version = session.api_version
      end

      def clear_session
        self.site = nil
        self.password = nil
        self.user = nil
        self.headers.delete('X-Shopify-Access-Token')
      end

      def api_version
        if _api_version_defined?
          _api_version
        elsif superclass != Object && superclass.site
          superclass.api_version.dup.freeze
        else
          ApiVersion::NullVersion
        end
      end

      def api_version=(version)
        self._api_version = if ApiVersion::NullVersion.matches?(version)
          ApiVersion::NullVersion
        else
          ApiVersion.find_version(version)
        end
      end

      def prefix(options = {})
        api_version.construct_api_path(resource_prefix(options))
      end

      def prefix_source
        ''
      end

      def resource_prefix(_options = {})
        ''
      end

      # Sets the \prefix for a resource's nested URL (e.g., <tt>prefix/collectionname/1.json</tt>).
      # Default value is <tt>site.path</tt>.
      def resource_prefix=(value)
        @prefix_parameters = nil

        resource_prefix_call = value.gsub(/:\w+/) { |key| "\#{URI::DEFAULT_PARSER.escape options[#{key}].to_s}" }

        silence_warnings do
          # Redefine the new methods.
          instance_eval(<<-RUBY_EVAL, __FILE__, __LINE__ + 1)
            def prefix_source() "#{value}" end
            def resource_prefix(options={}) "#{resource_prefix_call}" end
          RUBY_EVAL
        end
      rescue => e
        logger.try(:error, "Couldn't set prefix: #{e}\n  #{code}")
        raise
      end

      def prefix=(value)
        if value.start_with?('/admin')
          raise ArgumentError, "'#{value}' can no longer start /admin/. Change to using resource_prefix="
        end

        warn(
          '[DEPRECATED] ShopifyAPI::Base#prefix= is deprecated and will be removed in a future version. ' \
            'Use `self.resource_prefix=` instead.'
        )
        self.resource_prefix = value
      end

      alias_method :set_prefix, :prefix=

      def init_prefix(resource)
        init_prefix_explicit(resource.to_s.pluralize, "#{resource}_id")
      end

      def init_prefix_explicit(resource_type, resource_id)
        self.resource_prefix = "#{resource_type}/:#{resource_id}/"

        define_method(resource_id.to_sym) do
          @prefix_options[resource_id]
        end
      end

      def early_july_pagination?
        !!early_july_pagination
      end

      def version_validation!(minimum_version)
        available_in_version = ShopifyAPI::ApiVersion.find_version(minimum_version)

        unless ShopifyAPI::Base.api_version >= available_in_version
          raise NotImplementedError, "The minimum supported version is #{minimum_version}."
        end
      end    

      private

      attr_accessor :early_july_pagination

      def early_july_pagination_release!
        self.early_july_pagination = true
      end
    end

    # A method to manually load attributes from a \hash. Recursively loads collections of
    # resources. This method is called in +initialize+ and +create+ when a \hash of attributes
    # is provided.
    #
    # ==== Examples
    #   my_attrs = {:name => 'J&J Textiles', :industry => 'Cloth and textiles'}
    #   my_attrs = {:name => 'Marty', :colors => ["red", "green", "blue"]}
    #
    #   the_supplier = Supplier.find(:first)
    #   the_supplier.name # => 'J&M Textiles'
    #   the_supplier.load(my_attrs)
    #   the_supplier.name('J&J Textiles')
    #
    #   # These two calls are the same as Supplier.new(my_attrs)
    #   my_supplier = Supplier.new
    #   my_supplier.load(my_attrs)
    #
    #   # These three calls are the same as Supplier.create(my_attrs)
    #   your_supplier = Supplier.new
    #   your_supplier.load(my_attrs)
    #   your_supplier.save
    def load(attributes, remove_root = false, persisted = false)
      unless attributes.respond_to?(:to_hash)
        raise ArgumentError, "expected attributes to be able to convert to Hash, got #{attributes.inspect}"
      end

      attributes = attributes.to_hash
      @prefix_options, attributes = split_options(attributes)

      if attributes.keys.size == 1
        remove_root = self.class.element_name == attributes.keys.first.to_s
      end

      attributes = Formats.remove_root(attributes) if remove_root

      attributes.each do |key, value|
        @attributes[key.to_s] =
          case value
          when Array
            resource = nil
            value.map do |attrs|
              if attrs.is_a?(Hash)
                resource ||= find_or_create_resource_for_collection(key)
                resource.new(attrs, persisted)
              else
                attrs.duplicable? ? attrs.dup : attrs
              end
            end
          when Hash
            resource = find_or_create_resource_for(key)
            resource.new(value, persisted)
          else
            value.duplicable? ? value.dup : value
          end
      end
      self
    end      

    def persisted?
      !id.nil?
    end

    private

    def only_id
      encode(only: :id, include: [], methods: [])
    end
  end
end
