control 'SV-220378' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be utilized only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'By default, MarkLogic does not allow any user to perform any actions within or against the system unless that user is assigned specific roles granting access/execution privileges.

All read, update, or execute privileges are defined by specifying applicable system roles/permissions.

1. Verify MarkLogic user-defined modules are created and stored with applicable document permissions.
2. Verify users interacting with the system are assigned to roles with the least amount of privileges required for a given user.
3. Navigate to the MarkLogic Admin page >> Security >> Users.
4. Validate all system users are assigned to roles with the least amount of privileges necessary while allowing them to interact with system resources and perform applicable actions based upon their use case.

If a user is assigned roles exceeding their required access/privilege level, this is a finding.

If custom modules are stored with unnecessary elevated document permissions, this is finding.'
  desc 'fix', 'Correcting issues with unnecessary elevated privileges, and access to or execution of system resources, is a two-step process.

Correcting custom code/module permissions:
When inserting custom code into a given Modules database, ensure those custom modules have the correct permissions applied by writing them to the database with the applicable/correct document permissions. The permissions should specify specific roles and permissions (i.e., read, update, execute)

Correcting User privileges:
1. Navigate to the MarkLogic Admin page >> Security >> Roles.
2. Select a role under consideration and add/remove specific roles or permissions allowing the required level of permissions for a given role.
3. Save the configuration.
4. Navigate to the MarkLogic Admin page >> Security >> Users.
5. Select a user under consideration and add or remove applicable roles providing the user with the least level of privileges required for acceptable interaction with the system.
6. Repeat as required for each User and Role (usually these are user-defined roles or users).'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22093r401585_chk'
  tag severity: 'medium'
  tag gid: 'V-220378'
  tag rid: 'SV-220378r855482_rule'
  tag stig_id: 'ML09-00-006800'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-22082r401586_fix'
  tag 'documentable'
  tag legacy: ['SV-110105', 'V-101001']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
