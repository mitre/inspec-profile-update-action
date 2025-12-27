control 'SV-90685' do
  title 'The OS X system firewall must be configured with a default-deny policy.'
  desc 'An approved firewall must be installed and enabled to work in concert with the OS X Application Firewall. When configured correctly, firewalls protect computers from network attacks by blocking or limiting access to open network ports.'
  desc 'check', 'Ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved firewall is loaded on the system. The recommended system is the McAfee HBSS.

If no firewall is installed on the system, this is a finding. 

If a firewall is installed and it is not configured with a "default-deny" policy, this is a finding.'
  desc 'fix', 'Install an approved HBSS or firewall solution onto the system and configure it with a "default-deny" policy.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75997'
  tag rid: 'SV-90685r1_rule'
  tag stig_id: 'AOSX-12-000155'
  tag gtitle: 'SRG-OS-000480-GPOS-00231'
  tag fix_id: 'F-82635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
