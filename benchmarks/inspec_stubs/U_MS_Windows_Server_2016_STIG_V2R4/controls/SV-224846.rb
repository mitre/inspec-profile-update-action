control 'SV-224846' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.

If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26537r465440_chk'
  tag severity: 'medium'
  tag gid: 'V-224846'
  tag rid: 'SV-224846r569186_rule'
  tag stig_id: 'WN16-00-000310'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26525r465441_fix'
  tag 'documentable'
  tag legacy: ['SV-87931', 'V-73279']
  tag cci: ['CCI-000366', 'CCI-002080']
  tag nist: ['CM-6 b', 'CA-3 (5)']
end
