control 'SV-219868' do
  title 'Changes to configuration options must be audited.'
  desc 'When standard auditing is in use, the AUDIT_SYS_OPERATIONS parameter is used to enable auditing of actions taken by the user SYS. The SYS user account is a shared account by definition and holds all privileges in the Oracle database. It is the account accessed by users connecting to the database with SYSDBA or SYSOPER privileges.'
  desc 'check', "For Unified or mixed auditing, from SQL*Plus:

select count(*) from audit_unified_enabled_policies where entity_name = 'SYS';

If less than one row is returned, this is a finding.

For Standard auditing, from SQL*Plus:

  select value from v$parameter where name = 'audit_sys_operations';

If the value returned is FALSE, this is a finding."
  desc 'fix', 'For Standard auditing, from SQL*Plus:

  alter system set audit_sys_operations = TRUE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.

If Unified Auditing is used:
To ensure auditable events are captured:
Link the oracle binary with uniaud_on, and then restart the database. Oracle Database Upgrade Guide describes how to enable unified auditing.

For additional information on creating audit policies, refer to the Oracle Database Security Guide
http://docs.oracle.com/database/121/DBSEG/audit_config.htm#CHDGBAAC'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21579r903018_chk'
  tag severity: 'medium'
  tag gid: 'V-219868'
  tag rid: 'SV-219868r903020_rule'
  tag stig_id: 'O121-BP-025800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21578r903019_fix'
  tag 'documentable'
  tag legacy: ['SV-76009', 'V-61519']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
