control 'SV-25215' do
  title 'Only administrators responsible for the system must have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights.  Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.

System administrators must log on to systems only using accounts with the minimum level of authority necessary.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group (see V-36434 in the Active Directory Domain STIG).  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from this.  AD admin platforms may use the Domain Admins group or a domain administrative group created specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG).

Standard user accounts must not be members of the built-in Administrators group.'
  desc 'check', 'Review the local Administrators group.  Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from this.  AD admin platforms may use the Domain Admins group or a domain administrative group created specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG).

Standard user accounts must not be members of the local administrator group.

If prohibited accounts are members of the local administrators group, this is a finding.'
  desc 'fix', 'Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator group.

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from this.  AD admin platforms may use the Domain Admins group or a domain administrative group created specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG).

Remove any standard user accounts.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-54675r2_chk'
  tag severity: 'high'
  tag gid: 'V-1127'
  tag rid: 'SV-25215r6_rule'
  tag gtitle: 'Restricted Administrator Group Membership'
  tag fix_id: 'F-58531r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
