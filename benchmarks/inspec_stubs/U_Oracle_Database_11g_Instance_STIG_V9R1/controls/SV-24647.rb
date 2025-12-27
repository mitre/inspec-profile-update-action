control 'SV-24647' do
  title 'Unauthorized user accounts should not exist.'
  desc 'Unauthorized user accounts provide unauthorized access to the database and may allow access to database objects. Only authorized users should be granted database accounts.'
  desc 'check', 'Review procedures for ensuring authorization of new or re-assigned DBMS user accounts.

Requests for user account access to the DBMS should include documented approval by an authorized requestor.

Procedures should also include notification for a change in status, particularly cause for revocation of account access, to any DBMS accounts.
  
Review the user accounts listed either in the script report or manually against the authorized user list.

From SQL*Plus:
  select username from dba_users order by username;

If procedures for DBMS user account authorization are incomplete or not implemented, this is a Finding.

If any accounts listed are not clearly authorized, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures for authorizing creation, changes and deletions of user accounts.

Monitor user accounts to verify that they remain authorized.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29171r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2508'
  tag rid: 'SV-24647r1_rule'
  tag stig_id: 'DG0070-ORACLE11'
  tag gtitle: 'DBMS user account authorization'
  tag fix_id: 'F-26183r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
