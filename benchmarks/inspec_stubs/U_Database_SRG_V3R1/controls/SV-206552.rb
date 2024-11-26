control 'SV-206552' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

DBMSs may spawn additional external processes to execute procedures that are defined in the DBMS but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.'
  desc 'check', 'Review the database for definitions of application executable objects stored external to the database.

Determine if there are methods to disable use or access, or to remove definitions for external executable objects.

Verify each application executable object listed is authorized by the ISSO. If any are not, this is a finding.'
  desc 'fix', 'Disable use of or remove any external application executable object definitions that are not authorized.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6812r291324_chk'
  tag severity: 'medium'
  tag gid: 'V-206552'
  tag rid: 'SV-206552r617447_rule'
  tag stig_id: 'SRG-APP-000141-DB-000093'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6812r291325_fix'
  tag 'documentable'
  tag legacy: ['SV-42764', 'V-32427']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
