# ACME nsupdate [![Gem Version](https://badge.fury.io/rb/acme_nsupdate.svg)](https://rubygems.org/gems/acme_nsupdate)

ACME (Let's Encrypt) client with nsupdate (DDNS) integration.

CLI tool to obtain certificates via ACME and update the matching TLSA records.
The primary authentication method is http-01 via webroot for now, but dns-01 is supported too.

*Don't actually trust this, I wrote it for myself. Read and understand the code if you want to
actually use it. **There are no tests!***

## Installation

Install the gem:

```
$ gem install acme_nsupdate
```

## Usage

See the help:

```
$ acme_nsupdate --help
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/jhass/acme_nsupdate.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

