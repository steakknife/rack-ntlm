require 'net/ntlm'
require 'net/ldap'

DOMAIN_CACHE = {}
NTLM_GET_HASH_REGEX = /^(NTLM|Negotiate) (.+)/

module Rack

  class Ntlm
    
    def initialize(app, config = {})
      @app = app
      @config = {}.merge(config)
    end

    def ad_auth(name, domain, is_user)
    end

    def log(msg)
    end

    def call(env)
      if @config[:uri_pattern].blank?
        uri_matched = true
      else
        uri_matched = (env['PATH_INFO'] =~ @config[:uri_pattern])
      end

      if uri_matched
        if defined?(DEBUG) && DEBUG
          log "\n***"
          log "[RACKNTLM] Authenticating URL \"#{env['PATH_INFO']}\""
        end
      elsif env['HTTP_AUTHORIZATION']
        uri_matched = true
        if defined?(DEBUG) && DEBUG
          log "\n***"
          log "[RACKNTLM] Authorization: \"#{env['HTTP_AUTHORIZATION']}\""
        end
      end

      if uri_matched
        if env['HTTP_AUTHORIZATION'].blank?
          log "Starting NTLM authentication on URL: #{env['PATH_INFO']}"
          return [401, {'WWW-Authenticate' => "NTLM"}, []]
        elsif NTLM_GET_HASH_REGEX =~ env['HTTP_AUTHORIZATION']
          ntlm_hash = $2
          log "[RACKNTLM] Hash \"#{ntlm_hash}\"" if defined?(DEBUG) && DEBUG
          message = Net::NTLM::Message.decode64(ntlm_hash)

          log "Received NTLM authentication to #{env['PATH_INFO']} (type #{message.type})"
          domain_key = "#{env['REMOTE_ADDR']},#{env['PATH_INFO']}"
          log "Domain key: \"#{domain_key}\""

          if message.type == 1
            DOMAIN_CACHE.delete(domain_key) if DOMAIN_CACHE[domain_key]

            type2 = Net::NTLM::Message::Type2.new
            type2.flag |= Net::NTLM::FLAGS[:NTLM]
            type2.flag |= Net::NTLM::FLAGS[:NTLM2_KEY]
            type2.flag |= Net::NTLM::FLAGS[:KEY128]
            type2.flag |= Net::NTLM::FLAGS[:KEY56]
            type2.challenge = rand((2**64) - 1)

            log "Workstation: \"#{message.workstation}\""
            if message.workstation != message.domain
              log "Workstation #{message.workstation} on domain #{message.domain}"
              DOMAIN_CACHE[domain_key] = message.domain
            end

            return [401, {"WWW-Authenticate" => "NTLM " + type2.encode64}, []]

          elsif message.type == 3 
            unless message.user.blank?
              user = message.user.to_s
              user = Net::NTLM::decode_utf16le(message.user)
              env['USERNAME'] = user
              log "User: \"#{user}\""

              # For username logins, don't keep cache
              DOMAIN_CACHE.delete(domain_key) if DOMAIN_CACHE[domain_key]
            end

            unless message.workstation.blank?
              workstation = Net::NTLM::decode_utf16le(message.workstation)
              env['WORKSTATION'] = workstation
              log "Workstation: \"#{workstation}\""
            end

            domain = nil
            unless message.domain.blank?
              domain = Net::NTLM::decode_utf16le(message.domain)
              log "Domain: \"#{domain}\""
            end
            if domain.blank? && !DOMAIN_CACHE[domain_key].blank?
               domain = DOMAIN_CACHE[domain_key]
               log "Using previously cached domain: \"#{domain}\""
            end
            #domain = "WORKGROUP" if domain.blank?
            env['DOMAIN'] = domain

            if ENV['NO_AD'] && ENV['NO_AD'].to_i == 1
              log "Skipping LDAP Authentication"
              env['AD_NOAUTH'] = "1"

            elsif user.blank? || user[-1].chr == '$'
              #############################################
              # Computer authentication
              #############################################

              workstation += '$' if workstation[-1].chr != '$'

              @results = ad_auth(workstation, domain, false)
              if @results == -1 # ldap unavailable
                env['AD_NOAUTH'] = "1"
                log "Unable to authenticate workstation #{workstation} domain #{domain} (no LDAP server)"

              elsif @results
                env['AD_ENTRY'] = @results.first

              else
                log "Unable to authenticate workstation #{workstation} domain #{domain} (no such workstation)"
                env['AD_FAILEDAUTH'] = "1"
                #return [401, {}, ['You are not authorized to see this page']]
              end

            else 
              #############################################
              # User authentication
              #############################################

              @results = ad_auth(user, domain, true)
              if @results == -1 # ldap unavailable
                env['AD_NOAUTH'] = "1"
                log "Unable to authenticate user #{user} domain #{domain} (no LDAP server)"

              elsif @results
                env['AD_ENTRY'] = @results.first

              else
                log "Unable to authenticate user #{user} domain #{domain} (no such user)"
                env['AD_FAILEDAUTH'] = "1"
                #return [401, {}, ['You are not authorized to see this page']]
              end

            end # ENV['NO_AD'] && ENV['NO_AD'].to_i == 1

          else 
            return [401, {}, ['Your browser does not support Integrated Windows Authentication']]
          end # message.type
        end # if NTLM_GET_HASH_REGEX =~ env['HTTP_AUTHORIZATION']
      end # uri_matched

      @app.call(env)
    end # def call(env)
  
  end # Class
end # Module
