control 'SV-235113' do
  title 'The MySQL Database Server 8.0 must generate audit records when privileges/permissions are modified.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of individuals and groups privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users.

In a SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands.'
  desc 'check', %q(Check that MySQL Server Audit is being used for the STIG compliant audit.  

Check if MySQL audit is configured and enabled. The my.cnf file will set the variable audit_file.

To further check, execute the following query: 
SELECT PLUGIN_NAME, PLUGIN_STATUS
      FROM INFORMATION_SCHEMA.PLUGINS
      WHERE PLUGIN_NAME LIKE 'audit%';

The status of the audit_log plugin must be "active". If it is not "active", this is a finding.

Review audit filters and associated users by running the following queries:
SELECT `audit_log_filter`.`NAME`,
   `audit_log_filter`.`FILTER`
FROM `mysql`.`audit_log_filter`;

SELECT `audit_log_user`.`USER`,
   `audit_log_user`.`HOST`,
   `audit_log_user`.`FILTERNAME`
FROM `mysql`.`audit_log_user`;

All currently defined audits for the MySQL server instance will be listed. If no audits are returned, this is a finding.

Determine if rules are in place to capture the following types of commands related to permissions by running:
select * from mysql.audit_log_filter;

If the template SQL filter was used, it will have the name log_stig.

Review the filter values it will show filters for events of the type of the field general_sql_command.str for the following SQL statement types:
grant
grant_roles
revoke
revoke_all
revoke_roles
drop_role
alter_user_default_role
create_role
drop_role
grant_roles
revoke_roles
set_role
create_user
alter_user
drop_user
alter_user
alter_user_default_role
create_user
drop_user
rename_user
show_create_user)
  desc 'fix', 'Configure the MySQL Database Server to audit when privileges/permissions are added.

Add the following events to the MySQL Server Audit that is being used for the STIG compliance audit:
grant
grant_roles
revoke
revoke_all
revoke_roles
drop_role
alter_user_default_role
create_role
drop_role
grant_roles
revoke_roles
set_role
create_user
alter_user
drop_user
alter_user
alter_user_default_role
create_user
drop_user
rename_user
show_create_user

See the supplemental file "MySQL80Audit.sql".'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38332r623459_chk'
  tag severity: 'medium'
  tag gid: 'V-235113'
  tag rid: 'SV-235113r879866_rule'
  tag stig_id: 'MYS8-00-002600'
  tag gtitle: 'SRG-APP-000495-DB-000328'
  tag fix_id: 'F-38295r623460_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
