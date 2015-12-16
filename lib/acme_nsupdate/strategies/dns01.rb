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
        @client.logger.debug("Publishing challenges")
        nsupdate = @client.build_nsupdate

        challenges = @client.options[:domains].map {|domain|
          authorization = @client.client.authorize domain: domain
          challenge = authorization.dns01
          raise "Challenge dns-01 not supported by the given ACME server" unless challenge
          nsupdate.del(*record(domain, challenge, true)) unless @options[:keep]
          nsupdate.add(*record(domain, challenge), @options[:txt_ttl])

          [domain, challenge]
        }.to_h

        nsupdate.send

        challenges
      end

      def cleanup challenges
        @client.logger.info("Cleaning up")
        nsupdate = @client.build_nsupdate
        challenges.each do |domain, challenge|
          nsupdate.del(*record(domain, challenge))
        end
        nsupdate.send
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
