control 'SV-24573' do
  title 'Object permissions granted to PUBLIC should be restricted.'
  desc 'Permissions on objects may be granted to the user group PUBLIC. Because every database user is a member of the PUBLIC group, granting object permissions to PUBLIC gives all users in the database access to that object. In a secure environment, granting object permissions to PUBLIC should be restricted to those objects that all users are allowed to access. The policy does not require object permissions assigned to PUBLIC by the installation of Oracle Database server components be revoked (with exception of the packages listed in DO3475).'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select owner ||'.'|| table_name ||':'|| privilege from dba_tab_privs
  where grantee = 'PUBLIC'
  and owner not in
  ('SYS', 'CTXSYS', 'MDSYS', 'ODM', 'OLAPSYS', 'MTSSYS',
   'ORDPLUGINS', 'ORDSYS', 'SYSTEM', 'WKSYS', 'WMSYS',
   'XDB', 'LBACSYS', 'PERFSTAT', 'SYSMAN', 'DMSYS',
   'EXFSYS');

If any records that are not Oracle product accounts are returned, are not documented and authorized, this is a Finding.

NOTE:  This check may return false positives where other Oracle product accounts are not included in the exclusion list."
  desc 'fix', 'Revoke any privileges granted to PUBLIC for objects that are not owned by Oracle product accounts.

From SQL*Plus:

  revoke [privilege name] from [user name] on [object name];

Assign permissions to custom application user roles based on job functions:

From SQL*Plus:

  grant [privilege name] to [user role] on [object name];'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29485r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2589'
  tag rid: 'SV-24573r2_rule'
  tag stig_id: 'DO3689-ORACLE11'
  tag gtitle: 'Oracle object permission assignment to PUBLIC'
  tag fix_id: 'F-26551r1_fix'
  tag false_positives: 'This check may return false positives where other Oracle product accounts are not included in the exclusion list.'
  tag responsibility: 'Database Administrator'
end
