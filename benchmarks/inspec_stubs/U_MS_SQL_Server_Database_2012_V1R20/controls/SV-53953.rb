control 'SV-53953' do
  title 'SQL Server must check the validity of data inputs.'
  desc 'Invalid user input occurs when a user inserts data or characters into an application’s data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

SQL Server needs to validate the data user’s attempt to input to the application for processing. Rules for checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, acceptable values) are in place to verify inputs match specified definitions for format and content. Inputs passed to interpreters are prescreened to prevent the content from being unintentionally interpreted as commands.

A poorly designed database system can have many problems. A common issue with these types of systems is the missed opportunity to use constraints.

While this matter is of great importance to the secure operation of database management systems, the DBA in a typical installation will communicate with the application development/support staff to obtain assurance that this requirement is met.'
  desc 'check', 'Review SQL Server field definitions, constraints, and foreign keys to determine whether or not data being input into the database is valid.
If field definitions are not reflective of the data, this is a finding.

If column data types are not assigned correctly where required within the database, this is a finding.

If columns do not contain reasonable constraints based on column use, this is a finding.'
  desc 'fix', 'Use triggers, constraints, foreign keys, etc. to validate data input.

Modify SQL Server to properly use the correct column data types as required in the database.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47958r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41424'
  tag rid: 'SV-53953r3_rule'
  tag stig_id: 'SQL2-00-022500'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-46852r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
