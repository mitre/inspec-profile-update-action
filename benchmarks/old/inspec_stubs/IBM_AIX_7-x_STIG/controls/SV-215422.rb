control 'SV-215422' do
  title 'The control script lists of preloaded libraries must contain only absolute paths on AIX systems.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.'
  desc 'check', %q(Verify run control scripts' library preload list using command:

# grep -r LDR_PRELOAD /etc/rc* 
/etc/rc.teboot:export LDR_PRELOAD=/../usr/bin
/etc/rc.teboot:export LDR_PRELOAD=/usr/bin

This variable is formatted as a colon-separated list of paths. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, and this is a finding.)
  desc 'fix', "Edit the run control scripts' library preload list and remove relative paths."
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16620r294717_chk'
  tag severity: 'medium'
  tag gid: 'V-215422'
  tag rid: 'SV-215422r508663_rule'
  tag stig_id: 'AIX7-00-003127'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16618r294718_fix'
  tag 'documentable'
  tag legacy: ['V-91693', 'SV-101791']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
