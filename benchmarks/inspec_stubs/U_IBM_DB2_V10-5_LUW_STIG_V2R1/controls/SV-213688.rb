control 'SV-213688' do
  title 'DB2 must limit  privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to DB2.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Use the following query to find who has privileges to alter, drop, and create objects in the schemas:
DB2> SELECT * FROM SYSCAT.SCHEMAAUTH
 
If non-authorized users have privileges to create, alter, or drop objects, this is a finding.'
  desc 'fix', 'Use the appropriate variation of REVOKE (schema privileges) statement to remove the privileges from unauthorized users/roles/groups:
 DB2> REVOKE <ALTERIN/CREATEIN/DROPIN> ON SCHEMA <schema-name> FROM <USER/GROUP/PUBLIC/ROLE> 
 
For more on this topic, see the Help page on "REVOKE (schema privileges) statement":
http://www.ibm.com/support/knowledgecenter/en/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0000988.html'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14909r295113_chk'
  tag severity: 'medium'
  tag gid: 'V-213688'
  tag rid: 'SV-213688r879586_rule'
  tag stig_id: 'DB2X-00-002800'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-14907r295114_fix'
  tag 'documentable'
  tag legacy: ['SV-89139', 'V-74465']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
