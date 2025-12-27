control 'SV-214936' do
  title 'Windows Server 2019 must have a host-based firewall installed and enabled.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-16136r356140_chk'
  tag severity: 'medium'
  tag gid: 'V-214936'
  tag rid: 'SV-214936r569188_rule'
  tag stig_id: 'WN19-00-000280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16134r356141_fix'
  tag 'documentable'
  tag legacy: ['V-93571', 'SV-103657']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
