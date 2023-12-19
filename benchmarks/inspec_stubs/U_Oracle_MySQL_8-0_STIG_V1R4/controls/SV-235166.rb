control 'SV-235166' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to the MySQL Database Server 8.0, etc.) must be restricted to authorized users.'
  desc 'If the DBMS were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', "MySQL database objects do not have an owner. MySQL is a single instance and single database with multiple schemas (aliased to be called either schema or database). Permissions are based on schemas and schema objects and privileges include grants to objects or grants to allow users to further grants access to objects. To reiterate, there is not an object owner just rights assigned to schemas and the objects within them.

To determine rights to objects via schema, table, or user privileges run the following:
SELECT * FROM `information_schema`.`SCHEMA_PRIVILEGES`;
SELECT * FROM `information_schema`.`TABLE_PRIVILEGES`;
SELECT * FROM `information_schema`.`COLUMN_PRIVILEGES`;
SELECT * FROM `information_schema`.`USER_PRIVILEGES`;
SELECT * FROM `information_schema`.`ROLE_COLUMN_GRANTS`;
SELECT * FROM `information_schema`.`ROLE_TABLE_GRANTS`;

On a per-user basis, for example:
show grants for 'test'@'%'; 

If any database objects are found to have access by users not authorized to the database objects, this is a finding."
  desc 'fix', 'Assign ownership of authorized objects to authorized object owner accounts.

Review user accounts with the GRANT OPTION. 

REVOKE GRANT OPTION to limit users with grant privileges.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38385r623618_chk'
  tag severity: 'medium'
  tag gid: 'V-235166'
  tag rid: 'SV-235166r879586_rule'
  tag stig_id: 'MYS8-00-008700'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-38348r623619_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
