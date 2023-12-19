control 'SV-84383' do
  title 'Exchange application directory must be protected from unauthorized access.'
  desc 'Default product installations may provide more generous access permissions than are necessary to run the application. By examining and tailoring access permissions to more closely provide the least amount of privilege possible, attack vectors that align with user permissions are less likely to access more highly secured areas.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the authorized groups and users that have access to the Exchange application directories.

Verify the access permissions on the directory match the access permissions listed in the EDSP. 

If any group or user has different access permissions than those listed in the EDSP, this is a finding. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V15.'
  desc 'fix', 'Update the EDSP.

Remove or modify the group or user access permissions.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70209r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69761'
  tag rid: 'SV-84383r1_rule'
  tag stig_id: 'EX13-CA-000115'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-75971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
