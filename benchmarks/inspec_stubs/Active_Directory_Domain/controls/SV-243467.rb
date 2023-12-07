control 'SV-243467' do
  title 'Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory domain and domain controllers.'
  desc 'The Domain Admins group is a highly privileged group.  Personnel who are system administrators must log on to Active Directory systems only using accounts with the level of authority necessary. Only system administrator accounts used exclusively to manage an Active Directory domain and domain controllers may be members of the Domain Admins group. A separation of administrator responsibilities helps mitigate the risk of privilege escalation resulting from credential theft attacks.'
  desc 'check', 'Review the Domain Admins group in Active Directory Users and Computers.  Any accounts that are members of the Domain Admins group must be documented with the IAO.  Each Domain Administrator must have a separate unique account specifically for managing the Active Directory domain and domain controllers.  

If any account listed in the Domain Admins group is a member of other administrator groups including the Enterprise Admins group, domain member server administrators groups, or domain workstation administrators groups, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Domain Admins group.  Ensure that each member has a separate unique account that can only be used to manage the Active Directory domain and domain controllers.  Remove any Domain Admin accounts from other administrator groups.'
  impact 0.7
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46742r723434_chk'
  tag severity: 'high'
  tag gid: 'V-243467'
  tag rid: 'SV-243467r723436_rule'
  tag stig_id: 'AD.0002'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46699r723435_fix'
  tag 'documentable'
  tag legacy: ['V-36432', 'SV-47838']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
