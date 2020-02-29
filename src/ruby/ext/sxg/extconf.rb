require 'mkmf'

extension_name = "sxg"
dir_config(extension_name)

unless RUBY_PLATFORM.include? 'mswin'
  $CFLAGS << %[ -I.. -Wall -O3 -g -std=c11]
end

$LDFLAGS << " -lsxg"

create_makefile(extension_name)
