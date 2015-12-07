require "openssl"
require "pathname"

require "acme-client"

require "acme_nsupdate/strategy"
require "acme_nsupdate/nsupdate"

module AcmeNsupdate
  class Client
    class Error < RuntimeError
    end

    RENEWAL_THRESHOLD = 2592000 # 30*24*60*60, 30 days

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
      challenges = @verification_strategy.verify_domains
      logger.info "Requesting certificate"
      certificate = client.new_certificate csr
      write_files live_path, certificate, private_key
      write_files archive_path, certificate, private_key
      @verification_strategy.cleanup challenges unless @options[:keep]
      publish_tlsa_records certificate
    end

    def register_account
      unless account_key_path.exist?
        logger.debug "No key found at #{account_key_path}, registering"
        registration = client.register contact: "mailto:#{@options[:contact]}"
        registration.agree_terms
      end
    end

    def client
      @client ||= Acme::Client.new private_key: account_key, endpoint: @options[:endpoint]
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

      cert_path = live_path.join("cert.pem")
      return true unless cert_path.exist?

      cert = OpenSSL::X509::Certificate.new(cert_path.read)
      (cert.not_after - Time.now) <= RENEWAL_THRESHOLD
    end

    def build_nsupdate
      Nsupdate.new(logger).tap do |nsupdate|
        nsupdate.server @options[:master] if @options[:master]
        nsupdate.tsig *@options[:tsig].split(":") if @options[:tsig]
      end
    end

    def csr
      logger.debug "Generating CSR"
      Acme::CertificateRequest.new(names: @options[:domains])
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
      @archive_path ||= datadir.join("archive").join(Time.now.strftime("%Y%m%d%H%M%S")).join(@options[:domains].first).tap(&:mkpath)
    end

    def write_files path, certificate, key
      logger.info "Writing files to #{path}"
      logger.debug "Writing #{path.join("key.pem")}"
      path.join("privkey.pem").write key.to_pem
      logger.debug "Writing #{path.join("cert.pem")}"
      path.join("cert.pem").write certificate.to_pem
      logger.debug "Writing #{path.join("chain.pem")}"
      path.join("chain.pem").write certificate.chain_to_pem
      logger.debug "Writing #{path.join("fullchain.pem")}"
      path.join("fullchain.pem").write certificate.fullchain_to_pem
      # TODO Set permissions
    end

    def publish_tlsa_records certificate
      return if @options[:notlsa]
      logger.info "Publishing TLSA records"
      nsupdate = build_nsupdate
      content = "3 1 1 #{OpenSSL::Digest::SHA256.hexdigest(certificate.public_key.to_der)}"
      @options[:domains].each do |domain|
        @options[:tlsaports].each do |port|
          label = "_#{port}._tcp.#{domain}"
          nsupdate.del label, "TLSA", content
          nsupdate.add label, "TLSA", content, @options[:tlsa_ttl]
        end
      end
      nsupdate.send
    end
  end
end
