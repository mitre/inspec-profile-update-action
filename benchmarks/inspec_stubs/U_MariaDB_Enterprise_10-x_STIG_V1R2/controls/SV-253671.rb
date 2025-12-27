control 'SV-253671' do
  title 'MariaDB must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc 'Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the systems performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.'
  desc 'check', "MariaDB Enterprise Audit plugin stores audit filters in the table mysql.server_audit_filters. Any users with update/delete/insert access to this table can modify the audit filters. 

Users with global insert, update, delete, and/or drop privileges can modify audit filters. Find users with global insert, update, delete, and/or drop privileges: 

MariaDB> SELECT user, host, insert_priv, update_priv, delete_priv, drop_priv 
FROM mysql.user 
WHERE insert_priv = 'y'
OR update_priv = 'y'
OR delete_priv = 'y'
OR drop_priv = 'y';

Users with insert, update, delete, and/or drop privileges on the mysql database can modify audit filters. Find users with insert, update, delete, and/or drop privileges on the mysql database: 

MariaDB> SELECT user, host, insert_priv, update_priv, delete_priv, drop_priv 
FROM mysql.db 
WHERE db = 'mysql'
AND (insert_priv = 'y' 
  OR update_priv = 'y'
  OR delete_priv = 'y'
  OR drop_priv = 'y'
  );

Users with insert, update, delete, and/or drop privileges on the server_audit_filters and server_audit_users tables can modify audit filters. Find users with insert, update, delete, and/or drop privileges on the mysql database: 

MariaDB> SELECT user, host, db, table_name, grantor, table_priv, timestamp, column_priv
FROM mysql.tables_priv
WHERE db = 'mysql'
AND table_name IN ('server_audit_filters','server_audit_users')
AND (table_priv LIKE '%Insert%'
  OR table_priv LIKE '%Update%'
  OR table_priv LIKE '%Delete%'
  OR table_priv LIKE '%Drop%'
);

If any users with the above privileges are found which should not have access to modify audit filters, this is a finding."
  desc 'fix', "Grant the necessary privileges to authorized users. Example: 

MariaDB> GRANT ALL PRIVILEGES ON mysql.server_audit_filters TO 'username'@'host';
MariaDB> GRANT ALL PRIVILEGES ON mysql.server_audit_users TO 'username'@'host';

For users found with access who are not authorized to modify audit filters, review the user's privileges, and update accordingly."
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57123r841536_chk'
  tag severity: 'medium'
  tag gid: 'V-253671'
  tag rid: 'SV-253671r841538_rule'
  tag stig_id: 'MADB-10-000600'
  tag gtitle: 'SRG-APP-000090-DB-000065'
  tag fix_id: 'F-57074r841537_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
