require "openssl"
require "pathname"
require "logger"
require "time" # Workaround missing require in acme-client 0.4.0

require "acme-client"
require "faraday/detailed_logger"

require "acme_nsupdate/strategy"
require "acme_nsupdate/nsupdate"

module AcmeNsupdate
  class Client
    class Error < RuntimeError
    end

    class DebuggableClient < Acme::Client
      attr_accessor :logger

      def new_connection endpoint:
        super do |configuration|
          yield(configuration) if block_given?
          configuration.response :detailed_logger, @logger if @logger
        end
      end

    end

    RENEWAL_THRESHOLD = 2_592_000 # 30*24*60*60, 30 days

    attr_reader :options, :logger

    def initialize options
      @options = options
      @logger = Logger.new(STDOUT)
      @logger.level = Logger::INFO
      @logger.level = Logger::FATAL if @options[:quiet]
      @logger.level = Logger::DEBUG if @options[:verbose]
      @verification_strategy = Strategy.for(@options[:challenge]).new(self)
    end

    def run
      unless renewal_needed?
        logger.info "Existing certificate is still valid long enough."
        return
      end

      register_account
      order, challenges = @verification_strategy.verify_domains
      logger.info "Requesting certificate"
      certificate = fetch_certificate order
      write_files live_path, certificate, private_key
      write_files archive_path, certificate, private_key
      @verification_strategy.cleanup challenges unless @options[:keep]
      publish_tlsa_records certificate
    rescue Nsupdate::Error
      abort "nsupdate failed." # detail logged in Nsupdate
    end

    def register_account
      return if account_key_path.exist?

      logger.debug "No key found at #{account_key_path}, registering"
      client.new_account contact: "mailto:#{@options[:contact]}", terms_of_service_agreed: true
    end

    def client
      @client ||= DebuggableClient.new(private_key: account_key, directory: @options[:endpoint]).tap do |client|
        client.logger = @logger if @options[:verbose]
      end
    end

    def account_key_path
      @account_key_path ||= datadir.join ".#{@options[:contact]}.pem"
    end

    def datadir
      @datadir ||= Pathname.new(@options[:datadir]).tap(&:mkpath)
    end

    def account_key
      @account_key ||= read_or_create_key account_key_path
    end

    def read_or_create_key path
      logger.debug "Creating or reading #{path}"
      path.write OpenSSL::PKey::RSA.new @options[:keylength] unless path.exist?
      OpenSSL::PKey::RSA.new path.read
    end

    def renewal_needed?
      return true if @options[:force]

      cert_path = live_path.join("fullchain.pem")
      return true unless cert_path.exist?

      cert = OpenSSL::X509::Certificate.new(cert_path.read)
      (cert.not_after - Time.now) <= RENEWAL_THRESHOLD
    end

    def build_nsupdate
      Nsupdate.new(logger).tap do |nsupdate|
        nsupdate.server @options[:master] if @options[:master]
        nsupdate.tsig(*@options[:tsig].split(":")) if @options[:tsig]
      end
    end

    def fetch_certificate order
      order.finalize csr: csr
      while order.status == 'processing'
        sleep 3
        order.reload
      end
      raise "Failed to fetch certificate, order failed." unless order.status == 'valid'
      order.certificate
    end

    def csr
      logger.debug "Generating CSR"
      Acme::Client::CertificateRequest.new(names: @options[:domains], private_key: private_key)
    end

    def private_key
      @private_key ||= read_or_create_key private_key_path
    end

    def private_key_path
      @private_key_path ||= live_path.join("privkey.pem")
    end

    def live_path
      @live_path ||= datadir.join("live").join(@options[:domains].first).tap(&:mkpath)
    end

    def archive_path
      @archive_path ||= datadir.join("archive")
                               .join(Time.now.strftime("%Y%m%d%H%M%S"))
                               .join(@options[:domains].first)
                               .tap(&:mkpath)
    end

    def write_files path, certificate, key
      logger.info "Writing files to #{path}"
      logger.debug "Writing #{path.join("key.pem")}"
      path.join("privkey.pem").write key.to_pem
      path.join("privkey.pem").chmod(0600)
      logger.debug "Writing #{path.join("fullchain.pem")}"
      path.join("fullchain.pem").write certificate
    end

    def publish_tlsa_records certificate_pem
      return if @options[:notlsa]

      certificate = OpenSSL::X509::Certificate.new certificate_pem

      logger.info "Publishing TLSA records"
      old_contents = outdated_certificates.map {|certificate|
        "3 1 1 #{OpenSSL::Digest::SHA256.hexdigest(certificate.public_key.to_der)}"
      }.uniq
      content = "3 1 1 #{OpenSSL::Digest::SHA256.hexdigest(certificate.public_key.to_der)}"
      old_contents.delete(content)

      @options[:domains].each do |domain|
        nsupdate = build_nsupdate

        @options[:tlsaports].each do |port|
          restriction, port = port.split(":")
          restriction, port = port, restriction unless port
          label = "_#{port}._tcp.#{domain}"

          if restriction
            restrictions = restriction.delete("[]").split(" ")
            unless restrictions.include? domain
              logger.debug "Not publishing TLSA record for #{label}, not one of #{restrictions.join(" ")}"
              next
            end
          end

          old_contents.each do |old_content|
            nsupdate.del label, "TLSA", old_content unless @options[:keep]
          end
          nsupdate.del label, "TLSA", content
          nsupdate.add label, "TLSA", content, @options[:tlsa_ttl]
        end

        begin
          nsupdate.send
        rescue Nsupdate::Error
          # Continue trying other zones, errors logged in Nsupdate
        end
      end
    end

    def outdated_certificates
      domain = @options[:domains].first
      @outdated_certificates ||= datadir
        .join("archive")
        .children
        .select {|dir| dir.join(domain, "fullchain.pem").exist? }
        .sort_by(&:basename)
        .map {|path| OpenSSL::X509::Certificate.new path.join(domain, "fullchain.pem").read }
        .tap(&:pop) # keep current
        .tap(&:pop) # keep previous
    end
  end
end
