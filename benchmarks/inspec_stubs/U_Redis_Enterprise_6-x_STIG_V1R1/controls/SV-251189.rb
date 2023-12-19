control 'SV-251189' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be used only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.

Redis Enterprise comes with the ability to run Redis Enterprise software modules within each database to extend the database functionality.'
  desc 'check', 'To verify that each database is not using these modules, perform the following steps:
1. Log in to the Redis Enterprise control plane.
2. Navigate to the databases tab.
3. Inspect each database for Redis modules within the database application. If the databases display "None" next to the Redis Modules field, no modules are installed.

If a module is present and a necessary use case is not documented, this is a finding.'
  desc 'fix', 'To remove a module from the Redis Enterprise Software:
1. Log in to the adminUI as an administrator.
2. Navigate to the "settings" tab.
3. Under "redis modules" to the far-right of each individual module, click the trashcan icon to remove the associated module.

To remove a module from an existing database, the database needs to be recreated without the authorized modules and migrate all applications and data to the new database. Once a module is installed within a database, removal is not supported.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54624r804755_chk'
  tag severity: 'medium'
  tag gid: 'V-251189'
  tag rid: 'SV-251189r804757_rule'
  tag stig_id: 'RD6X-00-001100'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-54578r804756_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
