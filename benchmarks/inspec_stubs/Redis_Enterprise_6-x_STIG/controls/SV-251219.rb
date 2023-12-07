control 'SV-251219' do
  title 'Access to external executables must be disabled or restricted.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

DBMSs may spawn additional external processes to execute procedures that are defined in the DBMS but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than the DBMS and provide unauthorized access to the host system.'
  desc 'check', 'Redis Enterprise has this feature available if any object used is approved by the ISSO. By default, external executables are not included in Redis Enterprise, and only admin users on the Redis Enterprise web UI or admins who have direct access to the server can add them.

To determine what modules or executables are applied:
1. Log in to the Redis Enterprise web UI as an admin user.
2. Navigate to the settings and then Redis modules tabs.

Verify that no unapproved external executables exist. 

If external executables do exist and are not approved by the ISSO, this is a finding.'
  desc 'fix', 'To add or remove modules or executables:
1. Log in to the Redis Enterprise web UI as an admin user.
2. Navigate to the settings and then Redis modules tabs. From here, modules may be freely added or removed.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54654r804845_chk'
  tag severity: 'medium'
  tag gid: 'V-251219'
  tag rid: 'SV-251219r804847_rule'
  tag stig_id: 'RD6X-00-008300'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-54608r804846_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
