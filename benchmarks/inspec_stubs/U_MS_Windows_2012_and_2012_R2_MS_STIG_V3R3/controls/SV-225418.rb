control 'SV-225418' do
  title 'Only administrators responsible for the member server must have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights.  Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary.

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group (see V-36433 in the Active Directory Domain STIG).  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the built-in Administrators group.'
  desc 'check', 'Review the local Administrators group. Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group. 

Standard user accounts must not be members of the local Administrator group.

If prohibited accounts are members of the local Administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.'
  desc 'fix', 'Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain-joined member servers, replace the Domain Admins group with a domain member server administrator group.

Remove any standard user accounts.'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27117r471596_chk'
  tag severity: 'high'
  tag gid: 'V-225418'
  tag rid: 'SV-225418r569185_rule'
  tag stig_id: 'WN12-GE-000004-MS'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27105r471597_fix'
  tag 'documentable'
  tag legacy: ['SV-51511', 'V-1127']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
