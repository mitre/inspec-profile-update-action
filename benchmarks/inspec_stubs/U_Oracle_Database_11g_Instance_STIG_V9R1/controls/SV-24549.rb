control 'SV-24549' do
  title 'The DBA role should not be granted to unauthorized user accounts.'
  desc 'The DBA role is very powerful and access to it should be restricted. Verify that any database account granted the DBA role is explicitly authorized by the IAO. In addition to full access to database objects, access to the DBA role by unauthorized accounts may provide full access to the server. Verify that individual DBA accounts are created for each DBA and that the DBA accounts are used only for DBA functions.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee from dba_role_privs 
  where granted_role='DBA' 
  and grantee not in
  ('SYS', 'SYSTEM', 'SYSMAN', 'CTXSYS', 'WKSYS');

If any accounts are listed, review against the list of DBA accounts authorized by the IAO in the System Security Plan. 

If any accounts are assigned the DBA role and are not authorized by the IAO, this is a Finding. 

If any DBA roles are assigned to developer accounts and this is a production database, this is a Finding. 

If any DBA roles are assigned to shared accounts, this is a Finding."
  desc 'fix', 'Authorize and document all DBA role authorizations in the System Security Plan.

Revoke DBA role membership from unauthorized accounts.

Revoke DBA role membership from any accounts assigned to a developer job function on a shared production / development database.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29459r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2527'
  tag rid: 'SV-24549r2_rule'
  tag stig_id: 'DO3440-ORACLE11'
  tag gtitle: 'Oracle DBA role assignment'
  tag fix_id: 'F-26521r1_fix'
  tag responsibility: 'Information Assurance Officer'
end
