control 'SV-29505' do
  title 'Only administrators responsible for the system must have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary. 

For domain joined member servers, the Domain Admins group must be replaced by a domain member server administrator group.  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the built-in Administrators group.'
  desc 'check', 'Review the local Administrators group. Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain joined member servers, the Domain Admins group must be replaced by a domain member server administrator group.

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.'
  desc 'fix', 'Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain joined member servers, replace the Domain Admins group with a domain member server administrator group.

Remove any standard user accounts.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-44748r1_chk'
  tag severity: 'high'
  tag gid: 'V-1127'
  tag rid: 'SV-29505r2_rule'
  tag stig_id: '4.027-MS'
  tag gtitle: 'Restricted Administrator Group Membership'
  tag fix_id: 'F-41047r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
