control 'SV-224182' do
  title 'The EDB Postgres Advanced Server must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

Even when no such hijacking takes place, invalid input that is recorded in the database, whether accidental or malicious, reduces the reliability and usability of the system. Available protections include data types, referential constraints, uniqueness constraints, range checking, and application-specific logic. Application-specific logic can be implemented within the database in stored procedures and triggers, where appropriate.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered."
  desc 'check', %q(Review DBMS code (trigger procedures, functions), application code, settings, column and field definitions, and constraints to determine whether the database is protected against invalid input.

If code exists that allows invalid data to be acted upon or input into the database, this is a finding.

If column/field definitions do not exist in the database, this is a finding.

If columns/fields do not contain constraints and validity checking where required, this is a finding.

Where a column/field is noted in the system documentation as necessarily free-form, even though its name and context suggest that it should be strongly typed and constrained, the absence of these protections is not a finding.

Where a column/field is clearly identified by name, caption, or context as Notes, Comments, Description, Text, etc., the absence of these protections is not a finding.

Check application code that interacts with the EDB Postgres Advanced Server database for the use of prepared statements. If prepared statements are not used, this is a finding.

If EDB SQL/Protect is being used to monitor and protect the EDB Postgres Advanced Server database from possible SQL injection attacks, verify that it has been configured according to documented organizational needs.

1) Execute the following SQL as enterprisedb:

 SELECT name, setting FROM pg_settings WHERE name LIKE 'edb\_sql\_protect.%' ESCAPE '\';

If the results of the above query show that the edb_sql_protect.enabled parameter is set to 'off' or if the edb_sql_protect.level is not set to an approved value, this is a finding.

2) In all the databases that are to be monitored with EDB SQL/Protect, execute the following SQL as enterprisedb:

 \dn

If the "sqlprotect" schema is not listed, this is a finding.

3) In all the databases that are to be monitored with EDB SQL/Protect, execute the following SQL as enterprisedb:

 SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed, or the remaining settings are not set to approved values, this is a finding.)
  desc 'fix', 'Modify database code to properly validate data before it is put into the database or acted upon by the database.

Modify the database to contain column/field definitions for each column/field in the database.

Modify the database to contain constraints and validity checking on database columns and tables that require them for data integrity.

Use prepared statements for user supplied inputs.

Do not allow general users direct console access to the EDB Postgres Advanced Server database.

If EDB SQL/Protect is being used to monitor and protect the EDB Postgres Advanced Server database from possible SQL injection attacks, install and configure SQL/Protect as documented here:

 https://www.enterprisedb.com/docs/en/11.0/EPAS_Guide_v11/EDB_Postgres_Advanced_Server_Guide.1.048.html#'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25855r495564_chk'
  tag severity: 'medium'
  tag gid: 'V-224182'
  tag rid: 'SV-224182r508023_rule'
  tag stig_id: 'EP11-00-006200'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-25843r495565_fix'
  tag 'documentable'
  tag legacy: ['V-100387', 'SV-109491']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
