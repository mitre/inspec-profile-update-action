control 'SV-213855' do
  title 'SQL Server must isolate security functions from nonsecurity functions.'
  desc %q(An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are defined as "the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based".

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.

Database Management Systems typically separate security functionality from nonsecurity functionality via separate databases or schemas.  SQL Server's [master] database and [sys] schema are examples of this.  Further granularity of access protection is provided by assigning logins and users to appropriate server roles and database roles

Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and nonsecurity functionality is commingled, users who have access to nonsecurity functionality may be able to access security functionality.)
  desc 'check', 'Determine application-specific security objects (lists of permissions, additional authentication information, stored procedures, application specific auditing, etc.) which are being housed inside SQL server in addition to the built-in security objects.

Review permissions, both direct and indirect, on the security objects, both built-in and application-specific.  The functions and views provided in the supplemental file Permissions.sql can help with this.

If the database(s), schema(s) and permissions on security objects are not organized to provide effective isolation of security functions from nonsecurity functions, this is a finding.'
  desc 'fix', 'Where possible, locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic.

In all cases, use GRANT, REVOKE, DENY, ALTER ROLE … ADD MEMBER …  and/or  ALTER ROLE  …. DROP MEMBER statements to add and remove permissions on server-level and database-level security-related objects to provide effective isolation.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15074r312916_chk'
  tag severity: 'medium'
  tag gid: 'V-213855'
  tag rid: 'SV-213855r397747_rule'
  tag stig_id: 'SQL4-00-021500'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-15072r312917_fix'
  tag 'documentable'
  tag legacy: ['SV-82369', 'V-67879']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
