control 'SV-243462' do
  title 'The local Administrators group on the Windows PAW must only include groups with accounts specifically designated to administer the PAW.'
  desc 'A main security architectural construct of a PAW is to restrict access to the PAW from only specific privileged accounts designated for managing the high-value IT resources the PAW has been designated to manage. If unauthorized standard user accounts or unauthorized high-value administrative accounts are able to access a specific PAW, high-value IT resources and critical DoD information could be compromised.'
  desc 'check', 'Verify the PAW is configured to restrict access to privileged accounts specifically designated to administer the PAW:

- On the Windows PAW, verify the membership of the local Administrators group.
- Verify the only members in the local Administrators group are the group specifically designated for managing the PAW and local administrator(s).

If the local Administrators group includes any members not members of the specifically designated group for managing the PAW and local administrator(s), this is a finding.'
  desc 'fix', 'Restrict membership of the local Administrators group to only include members of the group specifically designated to manage the PAW and local administrator(s).

See the Microsoft PAW paper (https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/privileged-access-workstations) for more information (go to PAW Installation instructions).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows PAW'
  tag check_id: 'C-46737r722955_chk'
  tag severity: 'medium'
  tag gid: 'V-243462'
  tag rid: 'SV-243462r722957_rule'
  tag stig_id: 'WPAW-00-002300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-46694r722956_fix'
  tag 'documentable'
  tag legacy: ['V-78185', 'SV-92891']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
