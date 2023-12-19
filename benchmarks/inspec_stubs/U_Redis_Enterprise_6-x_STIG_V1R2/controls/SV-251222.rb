control 'SV-251222' do
  title 'Redis Enterprise DBMS must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'Redis Enterprise allows the user to configure unique users per role. Review roles and ensure roles use unique organizational principles per user to the database. Redis does come with a default user for backwards compatibility. This user may be disabled.'
  desc 'check', 'To audit this configuration:
1. Log in to Redis Enterprise Administrative Control Plane.
2. Go to databases tab.
3. Select the desired database and then the configuration subtab.
4. Verify that Default database access is enabled. 

If it is enabled, this is a finding.'
  desc 'fix', 'To fix this issue perform the following actions:

To audit this configuration:
1. Log in to Redis Enterprise Administrative Control Plane.
2. Go to databases tab.
3. Select each database and review the configuration by selecting edit.
4. Deselect the default database access tab.

This configuration will break applications designed for use with Redis 5 prior to ACLs.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54657r804854_chk'
  tag severity: 'medium'
  tag gid: 'V-251222'
  tag rid: 'SV-251222r804856_rule'
  tag stig_id: 'RD6X-00-008600'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-54611r804855_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
