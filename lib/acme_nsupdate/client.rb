require "openssl"
require "pathname"

require "acme-client"

require "acme_nsupdate/nsupdate"

module AcmeNsupdate
  class Client
    class Error < RuntimeError
    end 

    def initialize options
      @options = options
    end
    
    def run
      register_account
      challenges = verify_domains
      certificate = client.new_certificate csr
      write_files live_path, certificate, private_key
      write_files archive_path, certificate, private_key
      remove_records challenges
      publish_tlsa_records certificate
    end

    private

    def register_account
      unless account_key_path.exist?
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
      path.write OpenSSL::PKey::RSA.new @options[:keylength] unless path.exist?
      OpenSSL::PKey::RSA.new path.read
    end

    def verify_domains
      publish_challenges.tap do |challenges|
        wait_for_verification challenges
      end
    end

    def publish_challenges
      nsupdate = build_nsupdate

      challenges = @options[:domains].map {|domain|
        authorization = client.authorize domain: domain
        challenge = authorization.dns01
        nsupdate.del(*record(domain, challenge, true)) unless @options[:keep]
        nsupdate.add(*record(domain, challenge), @options[:ttl])
        [domain, challenge]
      }.to_h
      nsupdate.send
      
      challenges
    end

    def build_nsupdate
      Nsupdate.new.tap do |nsupdate|
        nsupdate.server @options[:master] if @options[:master]
        nsupdate.tsig *@options[:tsig].split(":") if @options[:tsig]
      end
    end

    def record domain, challenge, nodata=false
      ["#{challenge.record_name}.#{domain}", challenge.record_type].tap do |record|
        record << %("#{challenge.record_content}") unless nodata
      end 
    end

    def wait_for_verification challenges
      challenges.each_value(&:request_verification)      
      challenges.map {|_, challenge| Thread.new { sleep(5) while challenge.verify_status == "pending" } }.each(&:join)
      challenges.each do |domain, challenge|
        raise Error.new "Verification of #{domain} failed: #{challenge.error}" unless challenge.status == "valid"
      end
    end

    def csr
      csr = OpenSSL::X509::Request.new
      csr.public_key = private_key.public_key
      csr.subject = OpenSSL::X509::Name.new ["CN", @options[:domains].first, OpenSSL::ASN1::UTF8STRING]
      if @options[:domains].size > 1
        csr.add_attribute OpenSSL::X509::Extension.new("subjectAltName", @options[:domains].map {|domain| "DNS:#{domain}" }.join(", "), false)
      end
      csr.sign certificate_private_key, OpenSSL::Digest::SHA256.new
      csr
    end

    def private_key
      @private_key ||= read_or_create_key private_key_key_path
    end

    def private_key_path
      @private_key_path ||= live_path.join("key.pem")
    end

    def live_path
      @live_path ||= datadir.join("live").join(@options[:domain].first).tap(&:mkpath)
    end

    def archive_path
      @archive_path ||= datadir.join("archive").join(Time.now.strftime("%Y%m%d%H%M%S")).join(@options[:domain].first).tap(&:mkpath)
    end

    def write_files path, certificate, key
      # cert.pem
      # key.pem
      # chain.pem
      # fullchain.pem
      path.join("cert.pem").write certificate
      path.join("key.pem").write key
    end

    def remove_records challenges
      return if @options[:keep]
      nsupdate = build_nsupdate
      challenges.each do |domain, challenge|
        nsupdate.del *record(domain, challenge)
      end
      nsupdate.send
    end

    def publish_tlsa_records certificate
      return unless @options[:tlsa]
      nsupdate = build_nsupdate
      content = "3 1 1 #{OpenSSL::Digest::SHA256.hexdigest(certificate.public_key.to_der)}"
      @options[:domains].each do |domain|
        @options[:tlsaports].each do |port|
          label = "_#{port}._tcp.#{domain}"
          nsupdate.del label, "TLSA"
          nsupdate.add label, "TLSA", content 
        end
      end
      nsupdate.send
    end
  end
end
