control 'SV-81881' do
  title 'SQL Server must check the validity of all data inputs except those specifically identified by the organization.'
  desc 'Invalid user input occurs when a user inserts data or characters into an application’s data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

SQL Server needs to validate the data user’s attempt to input to the application for processing. Rules for checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, acceptable values) are in place to verify inputs match specified definitions for format and content. Inputs passed to interpreters are prescreened to prevent the content from being unintentionally interpreted as commands.

A poorly designed database system can have many problems. A common issue with these types of systems is the missed opportunity to use constraints.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', 'Review DBMS code (stored procedures, functions, triggers), application code, settings, column and field definitions, and constraints to determine whether the database is protected against invalid input.

If code exists that allows invalid data to be acted upon or input into the database, this is a finding.

If column/field definitions are not reflective of the data, this is a finding.

If columns/fields do not contain constraints and validity checking where required, this is a finding.

Where a column/field is noted in the system documentation as necessarily free-form, even though its name and context suggest that it should be strongly typed and constrained, the absence of these protections is not a finding.

Where a column/field is clearly identified by name, caption or context as Notes, Comments, Description, Text, etc., the absence of these protections is not a finding.'
  desc 'fix', 'Use triggers, constraints, foreign keys, etc. to validate data input.

Modify SQL Server to properly use the correct column data types as required in the database.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2014'
  tag check_id: 'C-67969r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67391'
  tag rid: 'SV-81881r2_rule'
  tag stig_id: 'SQL4-00-022500'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-73503r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
