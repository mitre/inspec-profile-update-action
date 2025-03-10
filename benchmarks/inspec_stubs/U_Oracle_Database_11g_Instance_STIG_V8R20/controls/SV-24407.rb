control 'SV-24407' do
  title 'Replication accounts should not be granted DBA privileges.'
  desc 'Replication accounts may be used to access databases defined for the replication architecture. An exploit of a replication on one database could lead to the compromise of any database participating in the replication that uses the same account name and credentials. If the replication account is compromised and it has DBA privileges, the database is at additional risk to unauthorized or malicious action.'
  desc 'check', 'If a review of the System Security Plan confirms the use of replication is not required, not permitted and the database is not configured for replication, this check is Not a Finding.

If any replication accounts are assigned DBA roles or roles with DBA privileges, this is a Finding.'
  desc 'fix', 'Restrict privileges assigned to replication accounts to the fewest possible privileges.

Remove DBA roles from replication accounts.

Create and use custom replication accounts assigned least privileges for supporting replication operations.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-938r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15619'
  tag rid: 'SV-24407r1_rule'
  tag stig_id: 'DG0100-ORACLE11'
  tag gtitle: 'DBMS replication account privileges'
  tag fix_id: 'F-2615r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
