control 'SV-219835' do
  title 'System Privileges must not be granted to PUBLIC.'
  desc 'System privileges can be granted to users and roles and to the user group PUBLIC. All privileges granted to PUBLIC are accessible to every user in the database. Many of these privileges convey considerable authority over the database and should be granted only to those persons responsible for administering the database. In general, these privileges should be granted to roles and then the appropriate roles should be granted to users. System privileges must never be granted to PUBLIC as this could allow users to compromise the database.'
  desc 'check', "From SQL*Plus:

  select privilege from dba_sys_privs where grantee = 'PUBLIC';

If any records are returned, this is a finding."
  desc 'fix', 'Revoke any system privileges assigned to PUBLIC:

From SQL*Plus:

  revoke [system privilege] from PUBLIC;

Replace [system privilege] with the named system privilege.

Note:  System privileges are not granted to PUBLIC by default and would indicate a custom action.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21546r533044_chk'
  tag severity: 'medium'
  tag gid: 'V-219835'
  tag rid: 'SV-219835r533046_rule'
  tag stig_id: 'O121-BP-022400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21545r533045_fix'
  tag 'documentable'
  tag legacy: ['SV-75925', 'V-61435']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
