control 'SV-44033' do
  title 'Exchange application directory must be protected from unauthorized access.'
  desc 'Default product installations may provide more generous access permissions than are necessary to run the application.  By examining and tailoring access permissions to more closely provide the least amount of privilege possible, attack vectors that align with user permissions are less likely to access more highly secured areas.'
  desc 'check', 'Obtain the Email Domain Security Plan (EDSP) and locate the authorized groups and users that have access to the Exchange application directories.

Verify the access permissions on the directory match the access permissions listed in the EDSP. If any group or user has different access permissions, this is a finding. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V14.'
  desc 'fix', 'Locate the Exchange application directory and Remove or modify the group or user access permissions. 

Note: The default installation directory is \\Program Files\\Microsoft\\Exchange Server\\V14.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41720r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33613'
  tag rid: 'SV-44033r1_rule'
  tag stig_id: 'Exch-2-828'
  tag gtitle: 'Exch-2-828'
  tag fix_id: 'F-37505r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
