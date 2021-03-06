require "fileutils"

require "acme_nsupdate/strategy"

module AcmeNsupdate
  module Strategies
    class Http01
      IDENTIFIER = "http-01"

      include Strategy

      def initialize client
        @client = client
      end

      def publish_challenges(order)
        map_authorizations(order) {|domain, authorization|
          challenge = authorization.http01
          abort "Challenge http-01 not supported by this ACME server" unless challenge

          path = path challenge
          @client.logger.debug "Writing #{path} for #{domain}"
          FileUtils.mkdir_p File.dirname path
          File.write path, challenge.file_content

          challenge
        }
      end

      def cleanup challenges
        @client.logger.info("Cleaning up challenges")
        challenges.each_value do |challenge|
          path = path challenge
          @client.logger.debug("Removing #{path}")
          File.delete path if File.exist? path
        end
      end

      private

      def path challenge
        File.join(@client.options[:webroot], challenge.filename)
      end
    end
  end
end
