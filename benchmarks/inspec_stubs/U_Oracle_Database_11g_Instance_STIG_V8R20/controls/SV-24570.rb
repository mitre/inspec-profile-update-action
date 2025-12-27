control 'SV-24570' do
  title 'Oracle roles granted using the WITH ADMIN OPTION should not be granted to unauthorized accounts.'
  desc "The WITH ADMIN OPTION allows the grantee to grant a role to another database account. Best security practice restricts the privilege of assigning privileges to authorized personnel. Authorized personnel include DBA's, object owners, and, where designed and included in the application's functions, application administrators. Restricting privilege-granting functions to authorized accounts can help decrease mismanagement of privileges and wrongful assignments to unauthorized accounts."
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee||': '||granted_role from dba_role_privs
  where grantee not in
  ('DBA', 'SYS', 'SYSTEM', 'WKSYS', 'LBACSYS',
   'WMSYS', 'OWBSYS', 'CTXSYS',
   'SPATIAL_CSW_ADMIN_USR',
   'SPATIAL_WFS_ADMIN_USR',
   'FLOWS_030000')
  and admin_option = 'YES' 
  and grantee not in
  (select distinct owner from dba_objects)
  and grantee not in
  (select grantee from dba_role_privs
   where granted_role = 'DBA')
  order by grantee;

Review the System Security Plan to confirm any grantees listed are IAO-authorized DBA accounts or application administration roles.

If any grantees listed are not authorized and documented, this is a Finding."
  desc 'fix', 'Revoke assignment of roles with the WITH ADMIN OPTION from unauthorized grantees and re-grant them without the option if required.

From SQL*Plus:

  revoke [role name] from [grantee];
  grant [role name] to [grantee];

Restrict use of the WITH ADMIN OPTION to authorized administrators.

Document authorized role assignments with the WITH ADMIN OPTION in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29481r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2574'
  tag rid: 'SV-24570r2_rule'
  tag stig_id: 'DO3622-ORACLE11'
  tag gtitle: 'Oracle roles granted WITH ADMIN OPTION'
  tag fix_id: 'F-26547r1_fix'
  tag responsibility: 'Database Administrator'
end
