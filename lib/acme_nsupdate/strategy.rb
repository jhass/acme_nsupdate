module AcmeNsupdate
  module Strategy
    class << self
      def strategies
        @strategies ||= {}
      end

      def for identifier
        strategies.fetch(identifier) { raise ArgumentError.new "Unknown strategy #{identifier}!" }
      end

      def included base
        strategies[base::IDENTIFIER] = base
      end
    end

    def verify_domains
      @client.logger.info("Validating domains")
      publish_challenges.tap do |challenges|
        wait_for_verification challenges
      end
    end


    private

    def map_authorizations
      @client.logger.debug "Publishing challenges for #{@client.options[:domains].join(", ")}"

      challenges = @client.options[:domains].map {|domain|
        authorization = @client.client.authorize domain: domain
        if authorization.status == "valid"
          @client.logger.debug("Skipping challenge for #{domain}, already valid.")
          next
        end

        challenge = yield domain, authorization
        unless challenge
          @client.logger.debug("Skipping challenge for #{domain}, not solvable.")
          next
        end

        [domain, challenge]
      }.compact.to_h
    end

    def wait_for_verification challenges
      @client.logger.debug("Requesting verification")
      challenges.each_value(&:request_verification)
      @client.logger.debug("Waiting for verification")
      challenges.map {|_, challenge| Thread.new { sleep(5) while challenge.verify_status == "pending" } }.each(&:join)
      challenges.each do |domain, challenge|
        raise "Verification of #{domain} failed: #{challenge.error}" unless challenge.status == "valid"
      end
    end
  end
end

require "acme_nsupdate/strategies/http01.rb"
require "acme_nsupdate/strategies/dns01.rb"
