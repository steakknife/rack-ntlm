require 'net/ntlm'

module Rack
  class Ntlm
    NTLM_GET_HASH_REGEX = /^(NTLM|Negotiate) (.+)/

    attr_reader :logger

    def initialize(app, config = {})
      @app    = app
      @config = {}.merge(config)
      @logger = @config[:logger] || ::Logger.new(STDOUT)
      @authenticator = @config[:authenticator]
    end

    def auth(env, user, workstation, domain)
      return @authenticator.auth(env, user, workstation, domain) if @authenticator && @authenticator.respond_to?(:auth)
      logger.error 'You must pass an :authenticator that responds to #auth(env, user, workstation, domain) during middleware setup'
    end

    def call(env)
      return @app.call(env) unless authenticatable_url?(env)
      return auth_response(env) if auth_required?(env)

      message = decode_message(env)

      if challenge_request?(message)
        return challenge_response

      elsif type3_request?(message)
        user        = extract_user(env, message)
        workstation = extract_workstation(env, message)
        domain      = extract_domain(env, message)

        auth(env, user, workstation, domain)

        return @app.call(env)
      end

      unsupported_response
    end


    ### States

    def authenticatable_url?(env)
      authenticatable = true  # authenticate by default

      if @config.has_key?(:agent_pattern)
        unless env['HTTP_USER_AGENT'] =~ @config[:agent_pattern]
          authenticatable = false
          logger.debug %/Skip authentication: User agent "#{env['HTTP_USER_AGENT']}" did not match "#{@config[:agent_pattern]}"/
        end
      end

      if @config.has_key?(:query_pattern)
        unless env['QUERY_STRING'] =~ @config[:query_pattern]
          authenticatable = false
          logger.debug %/Skip authentication: Query "#{env['QUERY_STRING']}" did not match "#{@config[:query_pattern]}"/
        end
      end

      if @config.has_key?(:uri_pattern)
        unless env['PATH_INFO'] =~ @config[:uri_pattern]
          authenticatable = false
          logger.debug %/Skip authentication: URI "#{env['PATH_INFO']}" did not match "#{@config[:uri_pattern]}"/
        end
      end

      if authenticatable
        logger.info 'Authenticating URL "%s"' % [env['PATH_INFO']]
      elsif env['HTTP_AUTHORIZATION']
        authenticatable = true
        logger.info 'Authorization: "%s"' % [env['HTTP_AUTHORIZATION']]
      end

      authenticatable
    end

    def auth_required?(env)
      !env.has_key?('HTTP_AUTHORIZATION')
    end

    def challenge_request?(message)
      1 == message.type
    end

    def type3_request?(message)
      3 == message.type
    end


    ### Responses

    def auth_response(env)
      logger.info "Starting NTLM authentication on URL: #{env['PATH_INFO']}"
      [401, {'WWW-Authenticate' => 'NTLM'}, []]
    end

    def unsupported_response
      [401, {}, ['Your browser does not support Integrated Windows Authentication']]
    end

    def challenge_response
      [401, {'WWW-Authenticate' => challenge_message}, []]
    end

    def challenge_message
      type2 = Net::NTLM::Message::Type2.new

      type2.flag      |= Net::NTLM::FLAGS[:NTLM]
      type2.flag      |= Net::NTLM::FLAGS[:NTLM2_KEY]
      type2.flag      |= Net::NTLM::FLAGS[:KEY128]
      type2.flag      |= Net::NTLM::FLAGS[:KEY56]
      type2.challenge = challenge_token

      'NTLM ' + type2.encode64
    end

    def challenge_token
      rand((2**64) - 1)
    end


    ### Decode

    def decode_message(env)
      NTLM_GET_HASH_REGEX =~ env['HTTP_AUTHORIZATION']
      ntlm_hash = $2
      #logger.debug %/Hash "#{ntlm_hash}"/
      message = Net::NTLM::Message.decode64(ntlm_hash)
      logger.debug "Message: #{message.inspect}"
      logger.info "Received NTLM authentication to #{env['PATH_INFO']} (type #{message.type})"
      message
    end

    def extract_domain(env, message)
      domain = Net::NTLM::decode_utf16le(message.domain.to_s)
      logger.info %/Domain: "#{domain}"/

      env['DOMAIN'] = domain

      domain
    end

    def extract_workstation(env, message)
      workstation = Net::NTLM::decode_utf16le(message.workstation.to_s)

      logger.info %/Workstation: "#{workstation}"/
      env['WORKSTATION'] = workstation

      workstation
    end

    def extract_user(env, message)
      user = Net::NTLM::decode_utf16le(message.user.to_s)

      logger.info %/User: "#{user}"/
      env['USERNAME'] = user

      user
    end

  end
end
