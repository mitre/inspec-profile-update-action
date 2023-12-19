control 'SV-254265' do
  title 'Windows Server 2022 must have a host-based firewall installed and enabled.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.

'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57750r848609_chk'
  tag severity: 'medium'
  tag gid: 'V-254265'
  tag rid: 'SV-254265r848611_rule'
  tag stig_id: 'WN22-00-000280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57701r848610_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
