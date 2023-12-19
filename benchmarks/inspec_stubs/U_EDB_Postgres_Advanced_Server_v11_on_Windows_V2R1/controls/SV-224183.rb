control 'SV-224183' do
  title 'The EDB Postgres Advanced Server and associated applications must reserve the use of dynamic code execution for situations that require it.'
  desc 'With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', %q(Review DBMS source code (stored procedures, functions, triggers) and application source code, to identify cases of dynamic code execution. Any user input should be handled through prepared statements.

If dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, this is a finding.

If EDB SQL/Protect is being used to monitor and protect the EDB Postgres Advanced Server database from possible SQL injection attacks, verify that it has been configured according to documented organizational needs.

1) Execute the following SQL as enterprisedb:

 SELECT name, setting FROM pg_settings WHERE name LIKE 'edb\_sql\_protect.%' ESCAPE '\';

If the results of the above query show that the edb_sql_protect.enabled parameter is set to 'off' or if the edb_sql_protect.level is not set to an approved value, this is a finding.

2) In all the databases that are to be monitored with EDB SQL/Protect, execute the following SQL as enterprisedb:

 \dn

If the "sqlprotect" schema is not listed, this is a finding.

3) In all the databases that are to be monitored with EDB SQL/Protect, execute the following SQL as enterprisedb:

 SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed or the remaining settings are not set to approved values, this is a finding.)
  desc 'fix', 'Where dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, modify the code to do so.

If EDB SQL/Protect is being used to monitor and protect the EDB Postgres Advanced Server database from possible SQL injection attacks, install and configure SQL/Protect as documented here:

 https://www.enterprisedb.com/docs/en/11.0/EPAS_Guide_v11/EDB_Postgres_Advanced_Server_Guide.1.048.html#'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25856r495567_chk'
  tag severity: 'medium'
  tag gid: 'V-224183'
  tag rid: 'SV-224183r508023_rule'
  tag stig_id: 'EP11-00-006300'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-25844r495568_fix'
  tag 'documentable'
  tag legacy: ['SV-109493', 'V-100389']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
