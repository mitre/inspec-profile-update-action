control 'SV-224159' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the EDB Postgres Advanced Server, etc.) must be restricted to authorized users.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', 'Use psql to connect to the db as enterprisedb and run this command:

\\dp *.*

If any unauthorized roles have unauthorized accesses, this is a finding.

Definitions of the access privileges are defined here:

http://www.postgresql.org/docs/current/static/sql-grant.html'
  desc 'fix', 'Revoke unauthorized privileges.

The syntax is:
 REVOKE <privilege> ON <object> FROM <role>.

Example:
 REVOKE INSERT ON a FROM PUBLIC;

See PostgreSQL documentation for details.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25832r495496_chk'
  tag severity: 'medium'
  tag gid: 'V-224159'
  tag rid: 'SV-224159r508023_rule'
  tag stig_id: 'EP11-00-003600'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-25820r495497_fix'
  tag 'documentable'
  tag legacy: ['SV-109449', 'V-100345']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
