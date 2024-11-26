control 'SV-219709' do
  title 'Object permissions granted to PUBLIC must be restricted.'
  desc 'Permissions on objects may be granted to the user group PUBLIC. Because every database user is a member of the PUBLIC group, granting object permissions to PUBLIC gives all users in the database access to that object. In a secure environment, granting object permissions to PUBLIC should be restricted to those objects that all users are allowed to access. The policy does not require object permissions assigned to PUBLIC by the installation of Oracle Database server components to be revoked (with the exception of the packages listed in O112-BP-021800).'
  desc 'check', "Run the SQL query:

select owner ||'.'|| table_name ||':'|| privilege from dba_tab_privs
where grantee = 'PUBLIC'
and owner not in
(<list of non-applicable accounts>);

(With respect to the list of special accounts that are excluded from this requirement, it is expected that the DBA will maintain the list to suit local circumstances, adding special accounts as necessary and removing any that are not supposed to be in use in the Oracle deployment that is under review.)

If any records that are not Oracle product accounts are returned, are not documented and authorized, this is a Finding.

NOTE:  This check may return false positives where other Oracle product accounts are not included in the exclusion list."
  desc 'fix', 'Revoke any privileges granted to PUBLIC for objects that are not owned by Oracle product accounts.

From SQL*Plus:

revoke [privilege name] from [user name] on [object name];

Assign permissions to custom application user roles based on job functions:

From SQL*Plus:

grant [privilege name] to [user role] on [object name];'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21434r306976_chk'
  tag severity: 'medium'
  tag gid: 'V-219709'
  tag rid: 'SV-219709r401224_rule'
  tag stig_id: 'O112-BP-022600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21433r306977_fix'
  tag 'documentable'
  tag legacy: ['SV-68229', 'V-53989']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
