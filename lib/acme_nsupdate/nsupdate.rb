module AcmeNsupdate
  class Nsupdate
    class Error < RuntimeError
    end

    def initialize(logger)
      @logger = logger
      @commands = []
    end

    def server server
      @commands << "server #{server}"
    end

    def tsig name, key
      @commands << "key #{name} #{key}"
    end

    def add label, type, data, ttl
      @commands << "update add #{label} #{ttl} #{type} #{data}"
    end

    def del label, type=nil, data=nil
      @commands << "update del #{label}#{" #{type}" if type}#{" #{data}" if data}"
    end

    def send
      @logger.debug("Starting nsupdate:")
      IO.popen("nsupdate", "r+") do |nsupdate|
        @commands.each do |command|
          @logger.debug "  #{command}"
          nsupdate.puts command
        end
        @logger.debug("  send")
        nsupdate.puts "send"
        nsupdate.close_write
        errors = nsupdate.readlines.map {|line| line[/^>\s*(.*)$/, 1].strip }.reject(&:empty?)
        unless errors.empty?
          errors = errors.join(" ")
          logger.warn "DNS update transaction failed: #{errors}"
          logger.warn "Transaction:"
          @commands.each do |command|
            logger.warn "  #{command}"
          end
          raise Error.new errors
        end
      end
    end
  end
end
