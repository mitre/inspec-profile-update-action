control 'SV-24673' do
  title 'The DBA role should not be assigned excessive or unauthorized privileges.'
  desc 'Oracle SYSDBA privileges include privileges to administer the database outside of database controls (when the database is shut down or open in restricted mode) in addition to all privileges controlled under database operation. Assignment of SYSDBA privileges in the Oracle password file to unauthorized persons can compromise all DBMS activities.'
  desc 'check', "From SQL*Plus:
  select username from v$pwfile_users
  where username not in
  (select grantee from dba_role_privs where granted_role='DBA')
  and username<>'INTERNAL'
  and (sysdba = 'TRUE' or sysoper='TRUE');

If any accounts are listed and are not authorized by the IAO in the System Security Plan, this is a Finding."
  desc 'fix', "If a REMOTE_LOGIN_PASSWORDFILE is in use (='EXCLUSIVE'), list database accounts assigned SYSDBA and SYSOPER database privileges and review for appropriate authorization.

Document authorized SYSDBA and SYSOPER users in the System Security Plan.

From SQL*Plus:
  select * from v$pwfile_users;

To revoke SYSDBA or SYSOPER from accounts:

From SQL*Plus:
  revoke sysdba from [username];
  revoke sysoper from [username];"
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-15804r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15615'
  tag rid: 'SV-24673r2_rule'
  tag stig_id: 'DG0085-ORACLE11'
  tag gtitle: 'Minimum DBA privilege assignment'
  tag fix_id: 'F-2586r1_fix'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
