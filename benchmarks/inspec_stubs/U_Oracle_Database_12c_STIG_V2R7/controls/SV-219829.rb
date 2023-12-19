control 'SV-219829' do
  title 'The Oracle WITH GRANT OPTION privilege must not be granted to non-DBA or non-Application administrator user accounts.'
  desc 'An account permission to grant privileges within the database is an administrative function. Minimizing the number and privileges of administrative accounts reduces the chances of privileged account exploitation. Application user accounts must never require WITH GRANT OPTION privileges since, by definition, they require only privileges to execute procedures or view / edit data.'
  desc 'check', "Execute the query:

select grantee||': '||owner||'.'||table_name
from dba_tab_privs 
where grantable = 'YES' 
and grantee not in (select distinct owner from dba_objects)
and grantee not in (select grantee from dba_role_privs where granted_role = 'DBA')
and table_name not like 'SYS_PLSQL_%'
order by grantee;

If any accounts are listed, this is a finding."
  desc 'fix', 'Revoke privileges granted the WITH GRANT OPTION from non-DBA and accounts that do not own application objects.

Re-grant privileges without specifying WITH GRANT OPTION.

Note: Do not revoke the system-generated grants such as those found on The SYS_PLSQL_% objects. They are system generated object types (a.k.a ShadowTypes) which are created internally by Oracle when you use the Pipelined Table Functions. This can result in (incorrect) compilation failures and/or invalidations when the users who are supposed to have access to the shadow types find themselves without access.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21540r533026_chk'
  tag severity: 'medium'
  tag gid: 'V-219829'
  tag rid: 'SV-219829r879887_rule'
  tag stig_id: 'O121-BP-021700'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21539r533027_fix'
  tag 'documentable'
  tag legacy: ['SV-75911', 'V-61421']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
