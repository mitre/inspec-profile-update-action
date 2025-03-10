control 'SV-224210' do
  title 'When invalid inputs are received, the EDB Postgres Advanced Server must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', %q(Review system documentation to determine how input errors are to be handled in general and if any special handling is defined for specific circumstances.

Review the source code for database program objects (stored procedures, functions, triggers) and application source code to identify how the system responds to invalid input.

If it does not implement the documented behavior, this is a finding.

Verify that EDB auditing is enabled.

 Execute the following SQL as enterprisedb:

 SHOW edb_audit;

If the result is not "csv" or "xml", this is a finding.

Verify that EDB Audit is logging errors at a minimum, and unless otherwise documented and approved, also logging DDL and DML actions performed on the EDB Postgres Advanced Server database.

 Execute the following SQL as enterprisedb:

 SHOW edb_audit_statement;

If the result is "all", this is not a finding.

Otherwise, if the result is not at least "error,ddl,dml" and if the current setting for this requirement has not been noted and approved by the organization in the system documentation, this is a finding.

If EDB SQL/Protect is being used to monitor and protect the EDB Postgres Advanced Server database from unexpected or unauthorized actions performed on database tables, verify that it has been configured according to documented organizational needs.

1) Execute the following SQL as enterprisedb:

 SELECT name, setting FROM pg_settings WHERE name LIKE 'edb\_sql\_protect.%' ESCAPE '\';

If the results of the above query show that the edb_sql_protect.enabled parameter is set to 'off' or if the edb_sql_protect.level is not set to an approved value, this is a finding.

2) In all the databases that are to be monitored with EDB SQL/Protect, execute the following SQL as enterprisedb:

 \dn

If the "sqlprotect" schema is not listed, this is a finding.

3) In all the databases that are to be monitored with EDB SQL/Protect, execute the following SQL as enterprisedb:

 SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed or the remaining settings are not set to approved values, this is a finding.)
  desc 'fix', %q(Revise and deploy the source code for database program objects (stored procedures, functions, triggers) and application source code, to implement the documented behavior.

To enable EDB Auditing, execute the following SQL statements as the enterprisedb user:

 ALTER SYSTEM SET edb_audit = csv;
 SELECT pg_reload_conf();

or

 ALTER SYSTEM SET edb_audit = xml;
 SELECT pg_reload_conf(); 

To configure the edb_audit_statement parameter, execute the following SQL statements as the enterprisedb user:

 ALTER SYSTEM SET edb_audit_statement = 'all';
 SELECT pg_reload_conf();

or

 Update the system documentation to note the organizationally approved setting and corresponding justification of the setting for this requirement.

If EDB SQL/Protect is being used to monitor and protect the EDB Postgres Advanced Server database from unexpected or unauthorized actions performed on database tables, install and configure SQL/Protect as documented in section "Protecting Against SQL Injection Attacks" in the EDB Postgres Advanced Server Guide available at the following link:

https://www.enterprisedb.com/edb-docs/p/edb-postgres-advanced-server)
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25883r495647_chk'
  tag severity: 'medium'
  tag gid: 'V-224210'
  tag rid: 'SV-224210r508023_rule'
  tag stig_id: 'EP11-00-009700'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-25871r495648_fix'
  tag 'documentable'
  tag legacy: ['SV-109545', 'V-100441']
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
