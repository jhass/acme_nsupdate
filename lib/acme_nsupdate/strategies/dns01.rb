require "acme_nsupdate/strategy"

module AcmeNsupdate
  module Strategies
    class Dns01
      IDENTIFIER = "dns-01"

      include Strategy

      def initialize client
        @client = client
      end

      def publish_challenges
        @client.logger.debug "Publishing challenges for #{@client.options[:domains].join(", ")}"

        challenges = @client.options[:domains].map {|domain|
          nsupdate = @client.build_nsupdate

          authorization = @client.client.authorize domain: domain
          challenge = authorization.dns01
          abort "Challenge dns-01 not supported by the given ACME server" unless challenge
          nsupdate.del(*record(domain, challenge, true)) unless @client.options[:keep]
          nsupdate.add(*record(domain, challenge), @client.options[:txt_ttl])
          nsupdate.send

          [domain, challenge]
        }.to_h

        @client.logger.info "Waiting 120 seconds for the DNS updates to go live"
        sleep 120 # We wait some time to give the slaves time to update

        challenges
      end

      def cleanup challenges
        @client.logger.info("Cleaning up challenges")
        challenges.each do |domain, challenge|
          nsupdate = @client.build_nsupdate
          nsupdate.del(*record(domain, challenge))
          nsupdate.send
        end
      end

      private

      def record domain, challenge, nodata=false
        ["#{challenge.record_name}.#{domain}", challenge.record_type].tap do |record|
          record << %("#{challenge.record_content}") unless nodata
        end
      end
    end
  end
end
