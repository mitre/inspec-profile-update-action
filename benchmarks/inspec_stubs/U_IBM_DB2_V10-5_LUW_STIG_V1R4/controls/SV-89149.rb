control 'SV-89149' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to DB2, etc.) must be restricted to authorized users.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Get the list of qualified and authorized owners from ISSO or DBA. 

The following view list information about privileges held by the users, the identities of users granting privileges, and the object ownership:
DB2> SELECT * FROM SYSIBMADM.PRIVILEGES

If any of the privileges is held by non-qualified and non-authorized individuals, this is a finding.'
  desc 'fix', 'Use the appropriate variation of the REVOKE command to revoke the privileges from non-qualified and non-authorized individuals:
DB2> REVOKE

Notes: Information about each database is automatically maintained in a set of views called the system catalog which is created when the database is created. This system catalog describes tables, columns, indexes, programs, privileges, and other objects.

information on the system catalog is available in the IBM knowledge base:

http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/c0005478.html?lang=en
 
http://www-01.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/c0005817.html'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74401r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74475'
  tag rid: 'SV-89149r1_rule'
  tag stig_id: 'DB2X-00-003300'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-81075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
