require "open3"

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
      Open3.popen3("nsupdate") do |stdin, stdout, stderr, wait_thr|
        @commands.each do |command|
          @logger.debug "  #{command}"
          stdin.puts command
        end
        @logger.debug("  send")
        stdin.puts "send"
        stdin.close
        errors = stdout.readlines.map {|line| line[/^>\s*(.*)$/, 1].strip }.reject(&:empty?)
        errors.concat stderr.readlines.map(&:strip).reject(&:empty?)
        stdout.close
        stderr.close
        unless errors.empty?
          errors = errors.join(" ")
          @logger.error "DNS update transaction failed: #{errors}"
          @logger.info "Transaction:"
          @commands.each do |command|
            @logger.info "  #{command}"
          end
          raise Error.new errors
        end
      end
    end
  end
end
