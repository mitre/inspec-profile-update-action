control 'SV-251619' do
  title 'IDMS must check the validity of all data input unless the organization says otherwise.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

With respect to database management systems, one class of threat is known as SQL injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

Even when no such hijacking takes place, invalid input that gets recorded in the database, whether accidental or malicious, reduces the reliability and usability of the system. Available protections include data types, referential constraints, uniqueness constraints, range checking, and application-specific logic. Application-specific logic can be implemented within the database in stored procedures and triggers, where appropriate."
  desc 'check', 'Validate SQL-defined tables, DISPLAY TABLE <schema-name>.<table-name> . If there is not a CHECK for the columns and accompanying accepted values, this is a finding.

Validate network-defined records, DISPLAY SCHEMA or DISPLAY RECORD. If there is no CALL to a procedure BEFORE STORE and BEFORE MODIFY, this is a finding. 

If the procedure does not validate the non-exempt columns, this is a finding.

Other applications and front-ends using mapping can use the automatic editing feature and edit and code tables to verify that an input value is valid.'
  desc 'fix', 'For SQL-defined tables, ALTER TABLE <schema-name>.<table-name> ADD CHECK (search-condition).

For network-defined records, MODIFY <record-name> CALL procedure BEFORE STORE/MODIFY. Create or update procedure to validate provided record field values.

Other applications and front-ends using mapping can use the automatic editing feature and edit and code tables to verify that an input value is valid.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55054r807722_chk'
  tag severity: 'medium'
  tag gid: 'V-251619'
  tag rid: 'SV-251619r807724_rule'
  tag stig_id: 'IDMS-DB-000480'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-55008r807723_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
