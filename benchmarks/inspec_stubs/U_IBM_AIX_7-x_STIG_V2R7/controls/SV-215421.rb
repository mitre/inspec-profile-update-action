control 'SV-215421' do
  title 'AIX control scripts library search paths must contain only absolute paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(Verify run control scripts' library search paths:

# grep -r LIBPATH /etc/rc* 
/etc/rc.teboot:export LIBPATH=/../usr/lib
/etc/rc.teboot:export LIBPATH=/usr/lib

This variable is formatted as a colon-separated list of paths. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, and this is a finding.)
  desc 'fix', %q(Edit run control scripts' library search "PATH" variables. Remove empty entries or entries that are not absolute paths.)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16619r294714_chk'
  tag severity: 'medium'
  tag gid: 'V-215421'
  tag rid: 'SV-215421r508663_rule'
  tag stig_id: 'AIX7-00-003126'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16617r294715_fix'
  tag 'documentable'
  tag legacy: ['SV-101789', 'V-91691']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
