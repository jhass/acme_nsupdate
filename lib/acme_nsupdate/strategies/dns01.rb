require "resolv"

require "acme_nsupdate/strategy"

module AcmeNsupdate
  module Strategies
    class Dns01
      IDENTIFIER = "dns-01"

      include Strategy

      def initialize client
        @client = client
      end

      def publish_challenges(order)
        challenges = map_authorizations(order) {|domain, authorization|
          challenge = authorization.dns01
          abort "Challenge dns-01 not supported by the given ACME server" unless challenge

          nsupdate = @client.build_nsupdate
          nsupdate.del(*record(domain, challenge, true)) unless @client.options[:keep]
          nsupdate.add(*record(domain, challenge), @client.options[:txt_ttl])
          nsupdate.send

          challenge
        }

        unless challenges.empty?
          @client.logger.info "Waiting up to 120 seconds for the DNS updates to go live"
          unless verify_live_challenges(@client.options[:master], challenges)
            raise AcmeNsupdate::Client::Error, "DNS challenges didn't appear on all nameservers within 120 seconds"
          end
        end

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

      def verify_live_challenges(primary, challenges, timeout=120)
        waited = 0
        public_nameservers(primary, challenges.first.first).all? {|nameserver|
          @client.logger.debug "Verifying DNS challenges are present on #{nameserver}"
          challenges.all? {|domain, challenge|
            name, type, content = record(domain, challenge)
            records = query(nameserver, name, type).map(&:strings).flatten.map {|content| %("#{content}") }
            @client.logger.debug "Got #{records.size} TXT records for #{name}: #{records.map(&:inspect).join(", ")}"
            if records.include? content
              true
            elsif waited >= timeout
              @client.logger.error "None matched, timeout reached, aborting"
              return false
            else
              @client.logger.debug "None matched, pausing for 5 seconds, already waited #{waited} seconds"
              sleep 5
              waited += 5
              redo
            end
          }
        }
      end

      def public_nameservers(primary, name)
        # We have to hack into this because it gives us no way to fetch the SOA on a NXDOMAIN
        authority = nil
        Resolv::DNS.open(nameserver: [primary], search: [], ndots: 1) do |dns|
          dns.lazy_initialize
          message = Resolv::DNS::Message.new
          message.rd = 1
          message.add_question(name, Resolv::DNS::Resource::IN::SOA)
          requester = dns.make_udp_requester

          begin
            sender = requester.sender(message, name, primary, 53)
            reply, _ = requester.request(sender, 10)
            authority = !reply.authority.empty? ? reply.authority.first.first.to_s : reply.answer.first[2].to_s
          ensure
            requester.close
          end
        end

        return [] unless authority
        query(primary, authority, :NS).map {|record| record.name.to_s }.uniq
      end

      def query(nameserver, name, qtype)
        Resolv::DNS.open(nameserver: [nameserver], search: [], ndots: 1) do |dns|
          return dns.getresources(name, Resolv::DNS::Resource::IN.const_get(qtype))
        end
      end

      def record domain, challenge, nodata=false
        ["#{challenge.record_name}.#{domain}", challenge.record_type].tap do |record|
          record << %("#{challenge.record_content}") unless nodata
        end
      end
    end
  end
end
