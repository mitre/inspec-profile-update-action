control 'SV-24531' do
  title 'Oracle application administration roles should be disabled if not required and authorized.'
  desc 'Application administration roles, which are assigned system or elevated application object privileges, should be protected from default activation. Application administration roles are determined by system privilege assignment (create / alter / drop user) and application user role ADMIN OPTION privileges.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee, granted_role from dba_role_privs
  where default_role='YES'
  and granted_role in
  (select grantee from dba_sys_privs where upper(privilege) like '%USER%')  
  and grantee not in
  ('DBA', 'SYS', 'SYSTEM', 'CTXSYS', 'DBA', 'IMP_FULL_DATABASE',
   'MDSYS', 'SYS', 'WKSYS')
  and grantee not in (select distinct owner from dba_tables)
  and grantee not in
  (select distinct username from dba_users where upper(account_status) like
   '%LOCKED%');

Review the list of accounts reported for this check and ensures that they are authorized application administration roles.

If any are not authorized application administration roles, this is a Finding."
  desc 'fix', 'For each role assignment returned, issue:

From SQL*Plus:

  alter user [username] default role all except [role];

If the user has more than one application administration role assigned, then you will have to remove assigned roles from default assignment and assign individually the appropriate default roles.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29449r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3438'
  tag rid: 'SV-24531r2_rule'
  tag stig_id: 'DO0340-ORACLE11'
  tag gtitle: 'Oracle application administration roles enablement'
  tag fix_id: 'F-26513r1_fix'
  tag responsibility: 'Database Administrator'
end
