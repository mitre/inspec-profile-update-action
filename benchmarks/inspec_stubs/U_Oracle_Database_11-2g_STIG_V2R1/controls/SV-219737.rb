control 'SV-219737' do
  title 'Replication accounts must not be granted DBA privileges.'
  desc 'Replication accounts may be used to access databases defined for the replication architecture. An exploit of a replication on one database could lead to the compromise of any database participating in the replication that uses the same account name and credentials. If the replication account is compromised and it has DBA privileges, the database is at additional risk to unauthorized or malicious action.'
  desc 'check', 'If a review of the System Security Plan confirms the use of replication is not required, not permitted and the database is not configured for replication, this check is Not a Finding.

If any replication accounts are assigned DBA roles or roles with DBA privileges, this is a Finding.'
  desc 'fix', 'Restrict privileges assigned to replication accounts to the fewest possible privileges.

Remove DBA roles from replication accounts.

Create and use custom replication accounts assigned least privileges for supporting replication operations.'
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21462r307060_chk'
  tag severity: 'medium'
  tag gid: 'V-219737'
  tag rid: 'SV-219737r401224_rule'
  tag stig_id: 'O112-BP-025500'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21461r307061_fix'
  tag 'documentable'
  tag legacy: ['SV-68285', 'V-54045']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
