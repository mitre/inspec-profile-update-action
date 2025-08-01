control 'SV-228400' do
  title 'The Exchange application directory must be protected from unauthorized access.'
  desc 'Default product installations may provide more generous access permissions than are necessary to run the application. By examining and tailoring access permissions to more closely provide the least amount of privilege possible, attack vectors that align with user permissions are less likely to access more highly secured areas.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) or document that contains this information.

Determine the authorized groups and users that have access to the Exchange application directories.

Verify the access permissions on the directory match the access permissions listed in the EDSP. 

If any group or user has different access permissions, this is a finding. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V15.'
  desc 'fix', 'Update the EDSP to specify the authorized groups and users that have access to the Exchange application directories or verify that this information is documented by the organization.

Navigate to the Exchange application directory and remove or modify the group or user access permissions. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V15.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30633r496996_chk'
  tag severity: 'medium'
  tag gid: 'V-228400'
  tag rid: 'SV-228400r612748_rule'
  tag stig_id: 'EX16-MB-000570'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-30618r496997_fix'
  tag 'documentable'
  tag legacy: ['SV-95425', 'V-80715']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
