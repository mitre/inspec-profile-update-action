control 'SV-24422' do
  title 'Administrative privileges should be assigned to database accounts via database roles.'
  desc 'Privileges granted outside the role of the administrative user job function are more likely to go unmanaged or without oversight for authorization. Maintenance of privileges using roles defined for discrete job functions offers improved oversight of administrative user privilege assignments and helps to protect against unauthorized privilege assignment.'
  desc 'check', "From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):

  select grantee||': '||privilege
  from dba_sys_privs
  where grantee not in
   ('SYS', 'SYSTEM', 'SYSMAN', 'CTXSYS', 'MDSYS', 'WKSYS')
  and grantee not in
  (select distinct granted_role from dba_role_privs)
  and privilege <> 'UNLIMITED TABLESPACE'
  order by grantee;

NOTE: Disregard any default database component account privilege assignments that may be returned. 

If administrative privileges have been assigned directly to an account, this is a Finding."
  desc 'fix', 'Revoke assigned administrative privileges from database accounts and assign to accounts via roles.

Document roles and assignments in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-962r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15627'
  tag rid: 'SV-24422r2_rule'
  tag stig_id: 'DG0117-ORACLE11'
  tag gtitle: 'DBMS administrative privilege assignment'
  tag fix_id: 'F-3786r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
