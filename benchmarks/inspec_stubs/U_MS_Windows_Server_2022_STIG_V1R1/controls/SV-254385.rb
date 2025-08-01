control 'SV-254385' do
  title 'Windows Server 2022 must only allow administrators responsible for the domain controller to have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems using only accounts with the minimum level of authority necessary. 

Standard user accounts must not be members of the built-in Administrators group.'
  desc 'check', 'This applies to domain controllers. A separate version applies to other systems.

Review the Administrators group. Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.

If the built-in Administrator account or other required administrative accounts are found on the system, this is not a finding.'
  desc 'fix', 'Configure the Administrators group to include only administrator groups or accounts that are responsible for the system.

Remove any standard user accounts.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57870r848969_chk'
  tag severity: 'high'
  tag gid: 'V-254385'
  tag rid: 'SV-254385r848971_rule'
  tag stig_id: 'WN22-DC-000010'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-57821r848970_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
