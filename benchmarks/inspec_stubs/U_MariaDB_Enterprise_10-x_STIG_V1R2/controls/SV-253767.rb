control 'SV-253767' do
  title 'MariaDB must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:

CREATE
ALTER
DROP
GRANT
REVOKE

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', 'Check what filters are in place by running the following as an administrative user: 

MariaDB> SELECT * FROM mysql.server_audit_filters;

Verify audit filters are correctly configured to log desired actions per user. If not, this is a finding.'
  desc 'fix', 'Edit the necessary filters to include the desired logging actions. Exact steps vary depending on desired logging. 

Example named audit filter assigned to specific user: 

MariaDB> INSERT INTO mysql.server_audit_users (host, user, filtername)
   VALUES ("%", "user1", "filter_example");

MariaDB> SET GLOBAL server_audit_reload_filters=ON;'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57219r841824_chk'
  tag severity: 'medium'
  tag gid: 'V-253767'
  tag rid: 'SV-253767r841826_rule'
  tag stig_id: 'MADB-10-011500'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag fix_id: 'F-57170r841825_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
