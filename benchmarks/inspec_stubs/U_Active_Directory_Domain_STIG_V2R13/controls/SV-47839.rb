control 'SV-47839' do
  title 'Administrators must have separate accounts specifically for managing domain member servers.'
  desc 'Personnel who are system administrators must log on to domain systems only using accounts with the minimum level of authority necessary. Only system administrator accounts used exclusively to manage domain member servers may be members of an administrator group for domain member servers. A separation of administrator responsibilities helps mitigate the risk of privilege escalation resulting from credential theft attacks.'
  desc 'check', 'Review the membership groups in Active Directory Users and Computers.  Membership groups must be designated at the domain level specifically for domain member server administrators. Domain member server administrator groups and any accounts that are members of the groups must be documented with the IAO.  Each member server administrator must have a separate unique account specifically for managing member servers.  

If any account listed in a domain member server administrator group is a member of other administrator groups including the Enterprise Admins group, the Domain Admins group, or domain workstation administrator groups, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of domain member server administrator groups.  Ensure that each member has a separate unique account that can only be used to manage domain member servers.  Remove any domain member server accounts from other administrator groups.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-44675r3_chk'
  tag severity: 'medium'
  tag gid: 'V-36433'
  tag rid: 'SV-47839r2_rule'
  tag stig_id: 'AD.0003'
  tag gtitle: 'Domain Member Server Administrators Group Members'
  tag fix_id: 'F-40965r3_fix'
  tag 'documentable'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
