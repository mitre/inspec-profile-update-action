control 'SV-24925' do
  title 'System privileges granted using the WITH ADMIN OPTION should not be granted to unauthorized user accounts.'
  desc "The WITH ADMIN OPTION allows the grantee to grant a privilege to another database account. Best security practice restricts the privilege of assigning privileges to authorized personnel. Authorized personnel include DBA's, object owners, and, where designed and included in the application's functions, application administrators. Restricting privilege-granting functions to authorized accounts can help decrease mismanagement of privileges and wrongful assignments to unauthorized accounts."
  desc 'check', "From SQL*Plus:

  select grantee, privilege from dba_sys_privs
  where grantee not in
  ('SYS', 'SYSTEM', 'AQ_ADMINISTRATOR_ROLE', 'DBA',
   'MDSYS', 'LBACSYS', 'SCHEDULER_ADMIN',
   'WMSYS')
  and admin_option = 'YES'
  and grantee not in
  (select grantee from dba_role_privs where granted_role = 'DBA');

If any accounts are listed, this is a Finding."
  desc 'fix', 'Revoke assignment of privileges with the WITH ADMIN OPTION from unauthorized users and re-grant them without the option.

From SQL*Plus:

  revoke [privilege name] from user [username];

Replace [privilege name] with the named privilege and [username] with the named user.

Restrict use of the WITH ADMIN OPTION to authorized administrators.

Document authorized privilege assignments with the WITH ADMIN OPTION in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29475r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2561'
  tag rid: 'SV-24925r2_rule'
  tag stig_id: 'DO3609-ORACLE11'
  tag gtitle: 'System privileges granted WITH ADMIN OPTION'
  tag fix_id: 'F-26540r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
