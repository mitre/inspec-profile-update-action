control 'SV-214078' do
  title 'Execution of software modules (to include functions and trigger procedures) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, PostgreSQL needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be utilized only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Functions in PostgreSQL can be created with the SECURITY DEFINER option. When SECURITY DEFINER functions are executed by a user, said function is run with the privileges of the user who created it. 

To list all functions that have SECURITY DEFINER, as, the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 
$ psql -c "SELECT nspname, proname, proargtypes, prosecdef, rolname, proconfig FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE prosecdef OR NOT proconfig IS NULL" 

In the query results, a prosecdef value of "t" on a row indicates that that function uses privilege elevation. 

If elevation of PostgreSQL privileges is utilized but not documented, this is a finding. 

If elevation of PostgreSQL privileges is documented, but not implemented as described in the documentation, this is a finding. 

If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding.'
  desc 'fix', 'Determine where, when, how, and by what principals/subjects elevated privilege is needed.  

To change a SECURITY DEFINER function to SECURITY INVOKER, as the database administrator (shown here as "postgres"), run the following SQL: 

$ sudo su - postgres 
$ psql -c "ALTER FUNCTION <function_name> SECURITY INVOKER"'
  impact 0.5
  ref 'DPMS Target PostgreSQL 9.x'
  tag check_id: 'C-15294r360865_chk'
  tag severity: 'medium'
  tag gid: 'V-214078'
  tag rid: 'SV-214078r508027_rule'
  tag stig_id: 'PGS9-00-003600'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-15292r360866_fix'
  tag 'documentable'
  tag legacy: ['SV-87557', 'V-72905']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
