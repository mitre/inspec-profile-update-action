control 'SV-253269' do
  title 'Only accounts responsible for the administration of a system must have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights. Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group (see V-36434 in the Active Directory Domain STIG). Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Standard user accounts must not be members of the local administrators group.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Review the members of the Administrators group.
Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.'
  desc 'fix', 'Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Remove any standard user accounts.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56722r828889_chk'
  tag severity: 'high'
  tag gid: 'V-253269'
  tag rid: 'SV-253269r828891_rule'
  tag stig_id: 'WN11-00-000070'
  tag gtitle: 'SRG-OS-000312-GPOS-00123'
  tag fix_id: 'F-56672r828890_fix'
  tag 'documentable'
  tag cci: ['CCI-002135']
  tag nist: ['AC-2 (6)']
end
