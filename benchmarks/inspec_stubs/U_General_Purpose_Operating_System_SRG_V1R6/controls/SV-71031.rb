control 'SV-71031' do
  title 'The operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57341r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56771'
  tag rid: 'SV-71031r1_rule'
  tag stig_id: 'SRG-OS-000118-GPOS-00060'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-61667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
