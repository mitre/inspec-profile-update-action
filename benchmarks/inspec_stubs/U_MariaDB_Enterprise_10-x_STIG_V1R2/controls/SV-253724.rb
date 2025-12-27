control 'SV-253724' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, MariaDB needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be used only where necessary and protected from misuse.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', "Functions and Procedures in MariaDB all have DEFINER and SECURITY_TYPE options.

If SECURITY_TYPE = DEFINER then the function or procedure is run using the privileges of the DEFINER account. 

If SECURITY_TYPE = INVOKER, then they will be run using the privileges of the user invoking the function or procedure.

To list the values of the DEFINER and SECURITY_TYPE in functions and procedures as the database administrator, run the following SQL:

MariaDB> SELECT ROUTINE_NAME, ROUTINE_SCHEMA, ROUTINE_TYPE, DEFINER, SECURITY_TYPE FROM information_schema.routines WHERE ROUTINE_SCHEMA NOT IN ('sys','mysql');

Triggers in MariaDB have a DEFINER option.

For Triggers the value of the DEFINER determines the privileges to be used at trigger activation time.

To list the values of the DEFINER in Triggers, as the database administrator, run the following SQL:

MariaDB> SELECT trigger_schema, trigger_name, action_statement, definer FROM information_schema.triggers;

If elevation of MariaDB privileges is utilized but not documented, this is a finding.

If elevation of MariaDB privileges is documented, but not implemented as described in the documentation, this is a finding.

If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding."
  desc 'fix', 'Determine where, when, how, and by what principals/subjects elevated privilege is needed. 

To change the values of the SECURITY_TYPE for functions and procedures:

MariaDB> USE <database>;
MariaDB> ALTER FUNCTION  procedure_name | function_name  sql security  INVOKER | DEFINER ;

To change the values of the DEFINER for functions, procedures, and triggers, run the following SQL as the database administrator:

MariaDB> SHOW CREATE  function | procedure ;
MariaDB> DROP  function | procedure ;

Recreate the function or procedure using the results of the create statement (from the SHOW CREATE results above), with the definer set to the desired user.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57176r841695_chk'
  tag severity: 'medium'
  tag gid: 'V-253724'
  tag rid: 'SV-253724r841697_rule'
  tag stig_id: 'MADB-10-006900'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-57127r841696_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
