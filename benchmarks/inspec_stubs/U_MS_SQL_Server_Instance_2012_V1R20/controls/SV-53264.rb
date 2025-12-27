control 'SV-53264' do
  title 'SQL Server must isolate security functions from nonsecurity functions by means of separate security domains.'
  desc 'Security functions are defined as "the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based".

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.

Database Management Systems typically separate security functionality from nonsecurity functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and nonsecurity functionality is commingled, users who have access to nonsecurity functionality may be able to access security functionality.'
  desc 'check', 'Determine elements of security functionality (lists of permissions, additional authentication information, stored procedures, application specific auditing, etc.) which are being housed inside SQL server.

For any elements found, check SQL Server to determine if these objects or code implementing security functionality are located in a separate security domain, such as a separate database or schema created specifically for security functionality.

Run the following queryto list all the user-defined databases:
SELECT Name 
FROM sys.databases 
WHERE database_id > 4 
ORDER BY 1;

If security-related database objects or code are not kept separate, this is a finding.'
  desc 'fix', 'Locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47565r3_chk'
  tag severity: 'medium'
  tag gid: 'V-40910'
  tag rid: 'SV-53264r3_rule'
  tag stig_id: 'SQL2-00-021500'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-46192r1_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
