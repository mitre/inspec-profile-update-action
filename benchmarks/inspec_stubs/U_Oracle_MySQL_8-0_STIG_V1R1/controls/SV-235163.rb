control 'SV-235163' do
  title 'The MySQL Database Server 8.0 must limit privileges to change software modules, to include stored procedures, functions and triggers, and links to software external to the MySQL Database Server 8.0.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', "Review Server documentation to determine the authorized owner and users or groups with modify rights for this SQL instance's binary files. Additionally check the owner and users or groups with modify rights for shared software library paths on disk. 

If any unauthorized users are granted modify rights, this is a finding. 

A plugin located in a plugin library file can be loaded at runtime with the INSTALL PLUGIN statement. The statement also registers the plugin in the mysql.plugin table to cause the server to load it on subsequent restarts. For this reason, INSTALL PLUGIN requires the INSERT privilege for the mysql.plugin table, and UNINSTALL requires DELETE.

Run the following statement to check for table specific privileges:
SELECT * FROM information_schema.TABLE_PRIVILEGES where (table_schema='mysql' and table_name=`plugin`) or (table_schema='mysql' and table_name='component';)

If privilege_type is INSERT or DELETE for an unauthorized user, this is a finding.

Run the following statement to check for global privileges:
select * from  information_schema.user_privileges where privilege_type='INSERT' or privilege_type='DELETE';

If privilege_type is INSERT or DELETE for an unauthorized user, this is a finding."
  desc 'fix', 'Remove permissions from users who should not have insert or update access to the mysql.plugin or mysql.component table.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38382r623609_chk'
  tag severity: 'medium'
  tag gid: 'V-235163'
  tag rid: 'SV-235163r638812_rule'
  tag stig_id: 'MYS8-00-008300'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-38345r623610_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
