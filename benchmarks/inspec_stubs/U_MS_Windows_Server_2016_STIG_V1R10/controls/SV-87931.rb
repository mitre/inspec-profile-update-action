control 'SV-87931' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73383r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73279'
  tag rid: 'SV-87931r1_rule'
  tag stig_id: 'WN16-00-000310'
  tag gtitle: 'SRG-OS-000480-GPOS-00231'
  tag fix_id: 'F-79723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
