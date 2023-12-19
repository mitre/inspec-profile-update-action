control 'SV-47840' do
  title 'Administrators must have separate accounts specifically for managing domain workstations.'
  desc 'Personnel who are system administrators must log on to domain systems only using accounts with the minimum level of authority necessary. Only system administrator accounts used exclusively to manage domain workstations may be members of an administrators group for domain workstations. A separation of administrator responsibilities helps mitigate the risk of privilege escalation resulting from credential theft attacks.'
  desc 'check', 'Review the membership groups in Active Directory Users and Computers.  Membership groups must be designated at the domain level specifically for domain workstation administrators. Domain workstation administrator groups and any accounts that are members of the groups must be documented with the IAO.  Each domain workstation administrator must have a separate unique account specifically for managing domain workstations.  

If any account listed in a domain workstation administrator group is a member of other administrator groups including the Enterprise Admins group, the Domain Admins group, or domain member server administrator groups, this is a finding.'
  desc 'fix', 'Create the necessary documentation that identifies the members of domain workstation administrator groups.  Ensure that each member has a separate unique account that can only be used to manage domain workstations.  Remove any domain workstation administrator accounts from other administrator groups.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-44676r3_chk'
  tag severity: 'medium'
  tag gid: 'V-36434'
  tag rid: 'SV-47840r2_rule'
  tag stig_id: 'AD.0004'
  tag gtitle: 'Domain Workstation Administrators Group Members'
  tag fix_id: 'F-40966r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
