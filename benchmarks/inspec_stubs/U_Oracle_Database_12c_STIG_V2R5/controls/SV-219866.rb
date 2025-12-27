control 'SV-219866' do
  title 'Replication accounts must not be granted DBA privileges.'
  desc 'Replication accounts may be used to access databases defined for the replication architecture. An exploit of a replication on one database could lead to the compromise of any database participating in the replication that uses the same account name and credentials. If the replication account is compromised and it has DBA privileges, the database is at additional risk to unauthorized or malicious action.'
  desc 'check', 'If a review of the System Security Plan confirms the use of replication is not required, not permitted and the database is not configured for replication, this check is not a finding.

If any replication accounts are assigned DBA roles or roles with DBA privileges, this is a finding.'
  desc 'fix', 'Restrict privileges assigned to replication accounts to the fewest possible privileges.

Remove DBA roles from replication accounts.

Create and use custom replication accounts assigned least privileges for supporting replication operations.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21577r533116_chk'
  tag severity: 'medium'
  tag gid: 'V-219866'
  tag rid: 'SV-219866r401224_rule'
  tag stig_id: 'O121-BP-025500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21576r533117_fix'
  tag 'documentable'
  tag legacy: ['SV-76003', 'V-61513']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
