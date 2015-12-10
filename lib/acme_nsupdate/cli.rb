require "slop"

require "acme_nsupdate/version"
require "acme_nsupdate/client"

module AcmeNsupdate
  class Cli
    def initialize argv=ARGV
      @options = Slop.parse(argv) do |o|
        o.array   "-d", "--domains",   "The domain to request a certificate for."
        o.string  "-m", "--master",    "The nameserver to use to provision the TXT record to. Defaults to the primary nameserver specifed in the SOA record."
        o.string  "-t", "--ttl",       "The TTLs of the TXT and TLSA records created, separated by a comma. Defaults to 60,43200", default: "60,43200"
        o.bool    "-k", "--keep",      "Skip removing any kind of temporary data after successfully obtaining the certificate."
        o.string  "-K", "--tsig",      "TSIG key to use for DNS updates. Expected format is name:key."
        o.string  "-e", "--endpoint",  "ACME API endpoint. Defaults to: https://acme-v01.api.letsencrypt.org", default: "https://acme-v01.api.letsencrypt.org"
        o.string  "-D", "--datadir",   "Base directory for certificates and account keys. Defaults to: /etc/letsencrypt", default: "/etc/letsencrypt"
        o.string  "-c", "--contact",   "Contact mail address."
        o.integer "-l", "--keylength", "Length of the generated RSA keys. Defaults to 2048.", default: 2048
        o.bool    "-T", "--notlsa",    "Do not publish TLSA records (publishing them drops all old ones). Defaults to no.", default: false
        o.array   "-p", "--tlsaports", "Ports to publish TLSA records for. Defaults to 443.", default: ["443"]
        o.string  "-C", "--challenge", "Challenge to use, either http-01 or dns-01. http-01 requires the webroot option. Defaults to http-01.", default: "http-01"
        o.string  "-w", "--webroot",   "Webroot to save http-01 challenges to."
        o.bool    "-V", "--verbose",   "Enable debug logging.", default: false
        o.bool    "-q", "--quiet",     "Only print error messages.", default: false
        o.bool    "-f", "--force",     "Force, even if cert is still valid.", default: false

        o.on "-v", "--version", "Display version." do
          puts "ACME nsupdate #{AcmeNsupdate::VERSION}"
          exit
        end

        o.on "-h", "--help", "Display this help." do
          puts o
          exit
        end
      end

      abort "Unexpected extra arguments #{@options.arguments}" unless @options.arguments.empty?

      @options = @options.to_h

      abort "You need to provide a domain!" if @options[:domains].empty?
      abort "You need to provide a contact mail address!" unless @options[:contact]
      abort "Invalid TSIG key: name or key missing!" if @options[:tsig] && !@options[:tsig].include?(":")
      abort "No webroot given or not writable!" if @options[:challenge] == "http-01" && (@options[:webroot].nil? || !File.writable?(@options[:webroot]))
      abort "Invalid TTL specification" unless @options[:ttl][/\A\d+,\d+\z/]
      abort "Can't silence output and enable debug logging at the same time." if @options[:verbose] && @options[:quiet]

      @options[:txt_ttl], @options[:tlsa_ttl] = @options[:ttl].split(",")
    end

    def run
      Client.new(@options).run
    end
  end
end
