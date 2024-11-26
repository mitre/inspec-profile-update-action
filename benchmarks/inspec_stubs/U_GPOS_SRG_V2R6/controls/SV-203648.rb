control 'SV-203648' do
  title 'The operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3773r557189_chk'
  tag severity: 'medium'
  tag gid: 'V-203648'
  tag rid: 'SV-203648r557191_rule'
  tag stig_id: 'SRG-OS-000118-GPOS-00060'
  tag gtitle: 'SRG-OS-000118'
  tag fix_id: 'F-3773r557190_fix'
  tag 'documentable'
  tag legacy: ['V-56771', 'SV-71031']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
