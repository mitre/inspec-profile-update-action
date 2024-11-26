control 'SV-251208' do
  title 'Redis Enterprise DBMS must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc 'Redis Enterprise permits the installation of logic modules through a control plane layer to the database, which requires privilege access to the control plane. This is provisioned for support during database runtime by a user with permissions to create a database. 

The ability to load modules directly within the database is not supported in Redis Enterprise; however, it is supported in open-source Redis.'
  desc 'check', 'Modules may be added to the Redis Enterprise control plane (adminUI) by navigating to the settings tab and then modules. Only admin users can view the settings tab.

To verify that users without explicit privileged status are not able to install modules, do the following:
1. Log in to the Redis Enterprise control plane (adminUI) with a user with administrative privileges.
2. Navigate to the access control tab.
3. Verify that only organizationally defined users have the appropriate privileges.

If a user is not assigned appropriate permissions, this is a finding.'
  desc 'fix', 'To ensure a regular user is unable to perform updates:
1. Log in to the Redis Enterprise control plane.
2. Navigate to the access controls tab.
3. In the users section, review each users role to ensure they are assigned the appropriate permissions.
4. If a user is not assigned appropriate permissions, ensure they are moved to an appropriate role.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54643r804812_chk'
  tag severity: 'medium'
  tag gid: 'V-251208'
  tag rid: 'SV-251208r855609_rule'
  tag stig_id: 'RD6X-00-007000'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag fix_id: 'F-54597r804813_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
