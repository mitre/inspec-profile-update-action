control 'SV-224964' do
  title 'Only administrators responsible for the domain controller must have Administrator rights on the system.'
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
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26655r465794_chk'
  tag severity: 'high'
  tag gid: 'V-224964'
  tag rid: 'SV-224964r569186_rule'
  tag stig_id: 'WN16-DC-000010'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-26643r465795_fix'
  tag 'documentable'
  tag legacy: ['SV-87871', 'V-73219']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
