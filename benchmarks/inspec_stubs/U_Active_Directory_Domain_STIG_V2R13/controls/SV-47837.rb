control 'SV-47837' do
  title 'Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest.'
  desc 'The Enterprise Admins group is a highly privileged group.  Personnel who are system administrators must log on to Active Directory systems only using accounts with the level of authority necessary. Only system administrator accounts used exclusively to manage the Active Directory Forest may be members of the Enterprise Admins group. A separation of administrator responsibilities helps mitigate the risk of privilege escalation resulting from credential theft attacks.'
  desc 'check', 'Review the Enterprise Admins group in Active Directory Users and Computers.  Any accounts that are members of the Enterprise Admins group must be documented with the IAO.  Each Enterprise Administrator must have a separate unique account specifically for managing the Active Directory forest.  

If any account listed in the Enterprise Admins group is a member of other administrator groups including the Domain Admins group, domain member server administrators groups, or domain workstation administrators groups, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Enterprise Admins group.  Ensure that each member has a separate unique account that can only be used to manage the Active Directory Forest.  Remove any Enterprise Admin accounts from other administrator groups.'
  impact 0.7
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-44673r3_chk'
  tag severity: 'high'
  tag gid: 'V-36431'
  tag rid: 'SV-47837r2_rule'
  tag stig_id: 'AD.0001'
  tag gtitle: 'Enterprise Admins Group Members'
  tag fix_id: 'F-40963r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
