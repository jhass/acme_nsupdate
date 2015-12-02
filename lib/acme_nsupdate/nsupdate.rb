module AcmeNsupdate
  class Nsupdate
    class Error < RuntimeError
    end

    def initialize
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
      IO.popen("nsupdate", "r+") do |nsupdate|
        @commands.each do |command|
          nsupdate.puts command
        end
        nsupdate.puts "send"
        nsupdate.close_write
        errors = nsupdate.readlines.map {|line| line[/^>\s*(.*)$/, 1].strip }.reject(&:empty?)
        raise Error.new(errors.join(" ")) unless errors.empty?
      end
    end
  end
end
