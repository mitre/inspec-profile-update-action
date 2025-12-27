control 'SV-207395' do
  title 'The VMM must disable local account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

VMMs need to track periods of inactivity and disable local account identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the VMM disables local account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to disable local account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7652r365595_chk'
  tag severity: 'medium'
  tag gid: 'V-207395'
  tag rid: 'SV-207395r378880_rule'
  tag stig_id: 'SRG-OS-000118-VMM-000590'
  tag gtitle: 'SRG-OS-000118'
  tag fix_id: 'F-7652r365596_fix'
  tag 'documentable'
  tag legacy: ['V-56991', 'SV-71251']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
