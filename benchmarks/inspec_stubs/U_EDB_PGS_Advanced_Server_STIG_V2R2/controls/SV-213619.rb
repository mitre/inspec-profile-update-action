control 'SV-213619' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be utilized only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Review the system documentation and source code of the application(s) using the database.

If elevation of DBMS privileges is used but not documented, this is a finding.

If elevation of DBMS privileges is documented but not implemented as described in the documentation, this is a finding.

If the privilege-elevation logic can be invoked in ways other than intended, in contexts other than intended, or by subjects/principals other than intended, this is a finding.

Execute the following SQL to find any users with BYPASS RLS permissions:

select rolname from pg_roles where rolbypassrls = true;

If any of these users are not superusers that should bypass RLS, this is a finding.'
  desc 'fix', 'Determine where, when, how, and by what principals/subjects elevated privilege is needed. 

Modify the system and the application(s) using the database to ensure privilege elevation is used only as required.

To alter a user to not allow bypassing RLS, execute the following SQL:

ALTER USER <user>  NOBYPASSRLS;'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14841r290169_chk'
  tag severity: 'medium'
  tag gid: 'V-213619'
  tag rid: 'SV-213619r508024_rule'
  tag stig_id: 'PPS9-00-007510'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-14839r290170_fix'
  tag 'documentable'
  tag legacy: ['SV-83595', 'V-68991']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
