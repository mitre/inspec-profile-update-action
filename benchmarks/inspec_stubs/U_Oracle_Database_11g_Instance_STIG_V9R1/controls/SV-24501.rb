control 'SV-24501' do
  title 'Database application user accounts should be denied storage usage for object creation within the database.'
  desc 'Tablespace storage quotas allow limits on storage use to be assigned to Oracle database users. Although this does not grant the user the privilege to create objects within the database, it provides an additional method to restrict unauthorized object creation and ownership.'
  desc 'check', "From SQL*Plus:

  select username, tablespace_name from dba_ts_quotas
  where username not in (select distinct owner from dba_objects)
  and username not in
  (select grantee from dba_role_privs where granted_role='DBA');

Review the list of user names returned.

If any belong to application users or application administrators, this is a Finding."
  desc 'fix', 'Assign tablespace quotas only to database accounts authorized to create and or own objects in the database.

Document authorized tablespace quotas for all accounts authorized to own objects in the System Security Plan.

Remove any quotas assigned to application users, application administrators, or any other unauthorized accounts.  

From SQL*Plus:

  alter user [username] quota 0 on [tablespace name];

Replace [username] with the named user and [tablespace name] with the identified tablespace name.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29415r2_chk'
  tag severity: 'low'
  tag gid: 'V-3847'
  tag rid: 'SV-24501r2_rule'
  tag stig_id: 'DO0157-ORACLE11'
  tag gtitle: 'Oracle storage use privileges'
  tag fix_id: 'F-26442r1_fix'
  tag responsibility: 'Database Administrator'
end
