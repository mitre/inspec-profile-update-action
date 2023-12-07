control 'SV-225416' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.  If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27115r471590_chk'
  tag severity: 'medium'
  tag gid: 'V-225416'
  tag rid: 'SV-225416r569185_rule'
  tag stig_id: 'WN12-FW-000001'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-27103r471591_fix'
  tag 'documentable'
  tag legacy: ['SV-55085', 'V-42420']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
