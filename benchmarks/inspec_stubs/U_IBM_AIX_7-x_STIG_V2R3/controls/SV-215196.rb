control 'SV-215196' do
  title 'The AIX root accounts list of preloaded libraries must be empty.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.'
  desc 'check', 'Verify the "LDR_PRELOAD" environment variable is empty or not defined for the "root" user using command: 
# env | grep LDR_PRELOAD 

If a path is returned, this is a finding.'
  desc 'fix', %q(Edit the "root" user's initialization files and remove any definition of "LDR_PRELOAD".)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16394r294039_chk'
  tag severity: 'medium'
  tag gid: 'V-215196'
  tag rid: 'SV-215196r508663_rule'
  tag stig_id: 'AIX7-00-001037'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16392r294040_fix'
  tag 'documentable'
  tag legacy: ['SV-101785', 'V-91687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
