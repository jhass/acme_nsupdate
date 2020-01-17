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
      order = @client.client.new_order identifiers: @client.options[:domains]
      challenges = publish_challenges(order).tap do |challenges|
        wait_for_verification challenges
      end
      [order, challenges]
    end


    private

    def map_authorizations(order)
      @client.logger.debug "Publishing challenges for #{@client.options[:domains].join(", ")}"

      order.authorizations.map {|authorization|
        if authorization.status == "valid"
          @client.logger.debug("Skipping challenge for #{authorization.domain}, already valid.")
          next
        end

        challenge = yield authorization.domain, authorization
        unless challenge
          @client.logger.debug("Skipping challenge for #{authorization.domain}, not solvable.")
          next
        end

        [authorization.domain, challenge]
      }.compact.to_h
    end

    def wait_for_verification challenges
      @client.logger.debug("Requesting verification")
      challenges.each_value(&:request_validation)
      @client.logger.debug("Waiting for verification")
      challenges.map {|_, challenge| Thread.new { sleep(5) while challenge.status == "pending" } }.each(&:join)
      challenges.each do |domain, challenge|
        raise "Verification of #{domain} failed: #{challenge.error}" unless challenge.status == "valid"
      end
    end
  end
end

require "acme_nsupdate/strategies/http01.rb"
require "acme_nsupdate/strategies/dns01.rb"
