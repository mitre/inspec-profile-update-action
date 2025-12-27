control 'SV-220090' do
  title 'The system must not be configured for network bridging.'
  desc 'Some systems have the ability to bridge or switch frames (link-layer forwarding) between multiple interfaces. This can be useful in a variety of situations but, if enabled when not needed, has the potential to bypass network partitioning and security.'
  desc 'check', 'Ask the system administrator if network bridging software is installed on the system or the system is configured for network bridging. If network bridging software is installed or the system is configured for network bridging, this is a finding.'
  desc 'fix', 'Remove the network bridging software and configuration from the system.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21799r489769_chk'
  tag severity: 'medium'
  tag gid: 'V-220090'
  tag rid: 'SV-220090r603266_rule'
  tag stig_id: 'GEN003619'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-21798r489770_fix'
  tag 'documentable'
  tag legacy: ['V-22421', 'SV-42308']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
