control 'SV-220298' do
  title 'The DBMS must isolate security functions from nonsecurity functions by means of separate security domains.'
  desc 'Security functions are defined as "the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based".

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models, structured, disciplined, and rigorous hardware and software development techniques, and sound system/security engineering principles.

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality must not be commingled with objects or code implementing application logic. When security and non-security functionality is commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Check DBMS settings to determine whether objects or code implementing security functionality are located in a separate security domain, such as a separate database or schema created specifically for security functionality.

If security-related database objects or code are not kept separate, this is a finding.

The Oracle elements of security functionality, such as the roles, permissions, and profiles, along with password complexity requirements, are stored in separate schemas in the database.  Review any site-specific applications security modules built into the database and determine what schema they are located in and take appropriate action.  The Oracle objects will be in the Oracle Data Dictionary.'
  desc 'fix', 'Locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic.  (This is the default behavior for Oracle.)  Review any site-specific applications security modules built into the database:   determine what schema they are located in and take appropriate action.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22013r392025_chk'
  tag severity: 'medium'
  tag gid: 'V-220298'
  tag rid: 'SV-220298r879643_rule'
  tag stig_id: 'O121-C2-018500'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-22005r392026_fix'
  tag 'documentable'
  tag legacy: ['SV-76265', 'V-61775']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
