control 'SV-219700' do
  title 'The Oracle WITH GRANT OPTION privilege must not be granted to non-DBA or non-Application administrator user accounts.'
  desc 'An account permission to grant privileges within the database is an administrative function. Minimizing the number and privileges of administrative accounts reduces the chances of privileged account exploitation. Application user accounts should never require WITH GRANT OPTION privileges since, by definition, they require only privileges to execute procedures or view / edit data.'
  desc 'check', "Execute the query:

select grantee||': '||owner||'.'||table_name
from dba_tab_privs 
where grantable = 'YES' 
and grantee not in (select distinct owner from dba_objects)
and grantee not in (select grantee from dba_role_privs where granted_role = 'DBA')
order by grantee;

If any accounts are listed, this is a finding."
  desc 'fix', 'Revoke privileges granted the WITH GRANT OPTION from non-DBA and accounts that do not own application objects.

Re-grant privileges without specifying WITH GRANT OPTION.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21425r306949_chk'
  tag severity: 'medium'
  tag gid: 'V-219700'
  tag rid: 'SV-219700r401224_rule'
  tag stig_id: 'O112-BP-021700'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21424r306950_fix'
  tag 'documentable'
  tag legacy: ['SV-68211', 'V-53971']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
