control 'SV-214828' do
  title 'The macOS system firewall must be configured with a default-deny policy.'
  desc 'An approved firewall must be installed and enabled to work in concert with the macOS Application Firewall. When configured correctly, firewalls protect computers from network attacks by blocking or limiting access to open network ports.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved firewall is loaded on the system. The recommended system is the McAfee HBSS.

If no firewall is installed on the system, this is a finding. 

If a firewall is installed and it is not configured with a "default-deny" policy, this is a finding.'
  desc 'fix', 'Install an approved HBSS or firewall solution onto the system and configure it with a "default-deny" policy.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16028r397056_chk'
  tag severity: 'medium'
  tag gid: 'V-214828'
  tag rid: 'SV-214828r609363_rule'
  tag stig_id: 'AOSX-13-000155'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16026r397057_fix'
  tag 'documentable'
  tag legacy: ['V-81517', 'SV-96231']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
