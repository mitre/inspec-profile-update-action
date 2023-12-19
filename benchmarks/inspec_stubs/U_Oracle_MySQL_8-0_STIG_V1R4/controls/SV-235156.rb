control 'SV-235156' do
  title 'The MySQL Database Server 8.0 must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

Even when no such hijacking takes place, invalid input that gets recorded in the database, whether accidental or malicious, reduces the reliability and usability of the system. Available protections include data types, referential constraints, uniqueness constraints, range checking, and application-specific logic. Application-specific logic can be implemented within the database in stored procedures and triggers, where appropriate."
  desc 'check', 'Review MySQL Database Server 8.0 code (stored procedures, functions, triggers), application code, settings, column and field definitions, triggers, and constraints to determine whether the database is protected against invalid input. If code exists that allows invalid data to be acted upon or input into the database, this is a finding.

If column/field definitions do not exist in the database, this is a finding.

If columns/fields do not contain constraints and validity checking where required, this is a finding.

Where a column/field is noted in the system documentation as necessarily free-form, even though its name and context suggest that it should be strongly typed and constrained, the absence of these protections is not a finding.

Where a column/field is clearly identified by name, caption or context as Notes, Comments, Description, Text, etc., the absence of these protections is not a finding.

MySQL Workbench Schema and Table Inspectors are effective tools for performing the review process, as are the MySQL Information Schema, and MySQL Schema tables.'
  desc 'fix', 'Use parameterized queries, constraints, foreign keys, etc., to validate data input.

Modify MySQL SQL Server to properly use the correct column data types as required in the database.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38375r623588_chk'
  tag severity: 'medium'
  tag gid: 'V-235156'
  tag rid: 'SV-235156r879652_rule'
  tag stig_id: 'MYS8-00-007300'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-38338r623589_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
