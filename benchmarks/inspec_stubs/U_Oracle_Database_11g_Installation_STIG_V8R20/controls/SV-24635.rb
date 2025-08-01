control 'SV-24635' do
  title 'DBMS privileges to restore database data or other DBMS configurations, features, or objects should be restricted to authorized DBMS accounts.'
  desc 'Unauthorized restoration of database data, objects, or other configuration or features can result in a loss of data integrity, unauthorized configuration, or other DBMS interruption or compromise.  Therefore, the capability to restore must be controlled.  Typically, only database administrators will have permission to restore a database.'
  desc 'check', 'Review DBMS accounts with elevated permissions (accounts granted ROLE permissions, DBA accounts, SCHEMA accounts, etc.).

If any accounts are not documented and authorized for RESTORE permissions, this is a Finding.'
  desc 'fix', 'Utilize DBMS roles that are authorized for database restore functions.

Restrict assignment of restore privileges.

Assign DBMS restoration roles only to authorized DBMS accounts.

Document assignments in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-24212r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15107'
  tag rid: 'SV-24635r2_rule'
  tag stig_id: 'DG0063-ORACLE11'
  tag gtitle: 'DBMS restore permissions'
  tag fix_id: 'F-20422r1_fix'
  tag responsibility: 'Database Administrator'
end
