control 'SV-221254' do
  title 'The Exchange application directory must be protected from unauthorized access.'
  desc 'Default product installations may provide more generous access permissions than are necessary to run the application. By examining and tailoring access permissions to more closely provide the least amount of privilege possible, attack vectors that align with user permissions are less likely to access more highly secured areas.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP). 

Determine the authorized groups and users that have access to the Exchange application directories.

Determine if the access permissions on the directory match the access permissions listed in the EDSP. 

If any group or user has different access permissions than listed in the EDSP, this is a finding. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V15.'
  desc 'fix', 'Update the EDSP to reflect the authorized groups and users that have access to the Exchange application directories.

Navigate to the Exchange application directory and remove or modify the group or user access permissions. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V15.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22969r411888_chk'
  tag severity: 'medium'
  tag gid: 'V-221254'
  tag rid: 'SV-221254r612603_rule'
  tag stig_id: 'EX16-ED-000580'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-22958r411889_fix'
  tag 'documentable'
  tag legacy: ['SV-95299', 'V-80589']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
