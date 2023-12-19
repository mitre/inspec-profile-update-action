control 'SV-24931' do
  title 'System Privileges should not be granted to PUBLIC.'
  desc 'System privileges can be granted to users and roles and to the user group PUBLIC. All privileges granted to PUBLIC are accessible to every user in the database. Many of these privileges convey considerable authority over the database and be granted only to those persons responsible for administering the database. In general, these privileges should be granted to roles and then the appropriate roles should be granted to users. System privileges should never be granted to PUBLIC as this could allow users to compromise the database.'
  desc 'check', "From SQL*Plus:

  select privilege from dba_sys_privs where grantee = 'PUBLIC';

If any records are returned, this is a Finding."
  desc 'fix', 'Revoke any system privileges assigned to PUBLIC:

From SQL*Plus:

  revoke [system privilege] from PUBLIC;

Replace [system privilege] with the named system privilege.

NOTE:  System privileges are not granted to PUBLIC by default and would indicate a custom action.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29479r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2564'
  tag rid: 'SV-24931r2_rule'
  tag stig_id: 'DO3612-ORACLE11'
  tag gtitle: 'Oracle system privilege assignment'
  tag fix_id: 'F-26544r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
