control 'SV-213707' do
  title 'DB2 must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. 

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Determine application-specific security objects (lists of permissions, additional authentication information, stored procedures, application specific auditing, etc.) which are being housed inside DB2 database in addition to the built-in security objects.

Review permissions, both direct and indirect, on the security objects, both built-in and application-specific.  The following functions and views provided can help with this:
DB2> SELECT LIBNAME, OWNER, LIBSCHEMA FROM SYSCAT.LIBRARIES 
DB2> SELECT MODULENAME, OWNER, MODULESCHEMA FROM SYSCAT.MODULES 
DB2> SELECT PKGNAME, OWNER, PKGSCHEMA FROM SYSCAT.PACKAGES 
DB2> SELECT ROUTINENAME, OWNER, ROUTINESCHEMA FROM SYSCAT.ROUTINES 
DB2> SELECT TRIGNAME, OWNER, TRIGSCHEMA FROM SYSCAT.TRIGGERS
DB2> SELECT * FROM SYSIBMADM.PRIVILEGES

If the database(s), schema(s) and permissions on security objects are not organized to provide effective isolation of security functions from nonsecurity functions, this is a finding.'
  desc 'fix', 'Where possible, locate security-related database objects and code in a separate database, schema, or other separate security domain from database objects and code implementing application logic.

In all cases, use GRANT, REVOKE, ALTER ROLE, DROP ROLE, statements to add and remove permissions on security-related objects to provide effective isolation.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14928r295170_chk'
  tag severity: 'medium'
  tag gid: 'V-213707'
  tag rid: 'SV-213707r879643_rule'
  tag stig_id: 'DB2X-00-005500'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-14926r295171_fix'
  tag 'documentable'
  tag legacy: ['SV-89177', 'V-74503']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
