control 'SV-243466' do
  title 'Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest.'
  desc 'The Enterprise Admins group is a highly privileged group.  Personnel who are system administrators must log on to Active Directory systems only using accounts with the level of authority necessary. Only system administrator accounts used exclusively to manage the Active Directory Forest may be members of the Enterprise Admins group. A separation of administrator responsibilities helps mitigate the risk of privilege escalation resulting from credential theft attacks.'
  desc 'check', 'Review the Enterprise Admins group in Active Directory Users and Computers.  Any accounts that are members of the Enterprise Admins group must be documented with the IAO.  Each Enterprise Administrator must have a separate unique account specifically for managing the Active Directory forest.  

If any account listed in the Enterprise Admins group is a member of other administrator groups including the Domain Admins group, domain member server administrators groups, or domain workstation administrators groups, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Enterprise Admins group.  Ensure that each member has a separate unique account that can only be used to manage the Active Directory Forest.  Remove any Enterprise Admin accounts from other administrator groups.'
  impact 0.7
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46741r723431_chk'
  tag severity: 'high'
  tag gid: 'V-243466'
  tag rid: 'SV-243466r723433_rule'
  tag stig_id: 'AD.0001'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46698r723432_fix'
  tag 'documentable'
  tag legacy: ['V-36431', 'SV-47837']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
