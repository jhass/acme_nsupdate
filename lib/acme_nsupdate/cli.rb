require "slop"

require "acme_nsupdate/client"

module AcmeNsupdate
  class Cli
    def initialize argv=ARGV
      @options = Slop.parse(argv) do |o|
        o.array   "-d", "--domains",   "The domain to request a certificate for."
        o.string  "-m", "--master",    "The nameserver to use to provision the TXT record to. Defaults to the primary nameserver specifed in the SOA record."
        o.integer "-t", "--ttl",       "The TTL of the TXT record created. Defaults to 60", default: 60
        o.bool    "-k", "--keep",      "Skip removing the TXT record after successfully obtaining the certificate."
        o.string  "-a", "--tsig",      "TSIG key to use for DNS updates. Expected format is name:key."
        o.string  "-e", "--endpoint",  "ACME API endpoint. Defaults to: https://acme-staging.api.letsencrypt.org", default: "https://acme-staging.api.letsencrypt.org"
        o.string  "-p", "--datadir",   "Base directory for certificates and account keys. Defaults to: /etc/letsencrypt", default: "/etc/letsencrypt"
        o.string  "-c", "--contact",   "Contact mail address."
        o.integer "-l", "--keylength", "Length of the generated RSA keys. Defaults to 2048.", default: 2048
        o.bool    "-r", "--tlsa",      "Publish TLSA records (drops all old ones). Defaults to yes.", default: true
        o.array   "-s", "--tlsaports", "Ports to publish TLSA records for. Defaults to 443.", default: ["443"]

        o.on "-h", "--help" do
          puts o
          exit
        end
      end
      
      abort "You need to provide a domain!" if @options[:domains].empty?
      abort "You need to provide a contact mail address!" unless @options[:contact]
      abort "Invalid TSIG key: name or key missing!" if @options[:tsig] && !@options[:tsig].include?(":")
    end

    def run
      Client.new(@options).run
    end
  end
end
