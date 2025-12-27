control 'SV-219739' do
  title 'Changes to configuration options must be audited.'
  desc 'The AUDIT_SYS_OPERATIONS parameter is used to enable auditing of actions taken by the user SYS. The SYS user account is a shared account by definition and holds all privileges in the Oracle database. It is the account accessed by users connecting to the database with SYSDBA or SYSOPER privileges.'
  desc 'check', "From SQL*Plus:

select value from v$parameter where name = 'audit_sys_operations';

If the value returned is FALSE, this is a Finding."
  desc 'fix', 'From SQL*Plus:

alter system set audit_sys_operations = TRUE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21464r307066_chk'
  tag severity: 'medium'
  tag gid: 'V-219739'
  tag rid: 'SV-219739r401224_rule'
  tag stig_id: 'O112-BP-025800'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21463r307067_fix'
  tag 'documentable'
  tag legacy: ['SV-68291', 'V-54051']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
