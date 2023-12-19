control 'SV-219712' do
  title 'Oracle application administration roles must be disabled if not required and authorized.'
  desc 'Application administration roles, which are assigned system or elevated application object privileges, should be protected from default activation. Application administration roles are determined by system privilege assignment (create / alter / drop user) and application user role ADMIN OPTION privileges.'
  desc 'check', "Run the SQL query:

select grantee, granted_role from dba_role_privs
where default_role='YES'
and granted_role in
(select grantee from dba_sys_privs where upper(privilege) like '%USER%') 
and grantee not in
(<list of non-applicable accounts>)
and grantee not in (select distinct owner from dba_tables)
and grantee not in
(select distinct username from dba_users where upper(account_status) like '%LOCKED%');

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

Review the list of accounts reported for this check and ensure that they are authorized application administration roles.

If any are not authorized application administration roles, this is a Finding."
  desc 'fix', 'For each role assignment returned, issue:

From SQL*Plus:

alter user [username] default role all except [role];

If the user has more than one application administration role assigned, then you will have to remove assigned roles from default assignment and assign individually the appropriate default roles.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21437r306985_chk'
  tag severity: 'medium'
  tag gid: 'V-219712'
  tag rid: 'SV-219712r401224_rule'
  tag stig_id: 'O112-BP-022900'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21436r306986_fix'
  tag 'documentable'
  tag legacy: ['SV-68235', 'V-53995']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
