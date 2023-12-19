control 'SV-219707' do
  title 'System Privileges must not be granted to PUBLIC.'
  desc 'System privileges can be granted to users and roles and to the user group PUBLIC. All privileges granted to PUBLIC are accessible to every user in the database. Many of these privileges convey considerable authority over the database and are granted only to those persons responsible for administering the database. In general, these privileges should be granted to roles and then the appropriate roles should be granted to users. System privileges should never be granted to PUBLIC as this could allow users to compromise the database.'
  desc 'check', "From SQL*Plus:

select privilege from dba_sys_privs where grantee = 'PUBLIC';

If any records are returned, this is a Finding."
  desc 'fix', 'Revoke any system privileges assigned to PUBLIC:

From SQL*Plus:

revoke [system privilege] from PUBLIC;

Replace [system privilege] with the named system privilege.

NOTE:  System privileges are not granted to PUBLIC by default and would indicate a custom action.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21432r306970_chk'
  tag severity: 'medium'
  tag gid: 'V-219707'
  tag rid: 'SV-219707r401224_rule'
  tag stig_id: 'O112-BP-022400'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21431r306971_fix'
  tag 'documentable'
  tag legacy: ['SV-68225', 'V-53985']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
