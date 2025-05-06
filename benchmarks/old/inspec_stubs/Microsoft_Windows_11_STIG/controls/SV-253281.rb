control 'SV-253281' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system. If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56734r828925_chk'
  tag severity: 'medium'
  tag gid: 'V-253281'
  tag rid: 'SV-253281r828927_rule'
  tag stig_id: 'WN11-00-000135'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56684r828926_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
