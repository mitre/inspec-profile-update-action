control 'SV-55078' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc 'A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections based on a set of rules.'
  desc 'check', 'Determine if a host-based firewall is installed and enabled on the system.  If a host-based firewall is not installed and enabled on the system, this is a finding.

The configuration requirements will be determined by the applicable firewall STIG.'
  desc 'fix', 'Install and enable a host-based firewall on the system.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-48760r5_chk'
  tag severity: 'medium'
  tag gid: 'V-42420'
  tag rid: 'SV-55078r1_rule'
  tag stig_id: 'WINFW-000001'
  tag gtitle: 'WINFW-000001'
  tag fix_id: 'F-47949r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
