control 'SV-215423' do
  title 'The global initialization file lists of preloaded libraries must contain only absolute paths on AIX.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.'
  desc 'check', %q(Check the global initialization files' library preload list using command:

# grep LDR_PRELOAD /etc/profile /etc/bashrc /etc/security/.login /etc/environment /etc/security/environ 
/etc/environment:LDR_PRELOAD=:/usr/bin/X11:/sbin:/usr/java7_64/jre/bin:/usr/java7_64/bin

This variable is formatted as a colon-separated list of paths. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, and this is a finding.)
  desc 'fix', "Edit the global initialization files and remove the relative path entry from the library preload list variable 'LDR_PRELOAD'."
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16621r294720_chk'
  tag severity: 'medium'
  tag gid: 'V-215423'
  tag rid: 'SV-215423r508663_rule'
  tag stig_id: 'AIX7-00-003128'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16619r294721_fix'
  tag 'documentable'
  tag legacy: ['SV-101793', 'V-91695']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
