control 'SV-24905' do
  title 'The Oracle WITH GRANT OPTION privilege should not be granted to non-DBA or non-Application administrator user accounts.'
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
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29463r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2533'
  tag rid: 'SV-24905r3_rule'
  tag stig_id: 'DO3451-ORACLE11'
  tag gtitle: 'WITH GRANT OPTION privileges'
  tag fix_id: 'F-26525r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
