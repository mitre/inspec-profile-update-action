control 'SV-219852' do
  title 'DBMS production application and data directories must be protected from developers on shared production/development DBMS host systems.'
  desc 'Developer roles must not be assigned DBMS administrative privileges to production DBMS application and data directories. The separation of production DBA and developer roles helps protect the production system from unauthorized, malicious or unintentional interruption due to development activities.'
  desc 'check', 'If the DBMS or DBMS host is not shared by production and development activities, this check is not a finding.

Review OS DBA group membership.

If any developer accounts, as identified in the System Security Plan, have been assigned DBA privileges, this is a finding.

Note: Though shared production/non-production DBMS installations was allowed under previous database STIG guidance, doing so may place it in violation of OS, Application, Network or Enclave STIG guidance. Ensure that any shared production/non-production DBMS installation meets STIG guidance requirements at all levels or mitigate any conflicts in STIG guidance with the AO.'
  desc 'fix', 'Create separate DBMS host OS groups for developer and production DBAs.

Do not assign production DBA OS group membership to accounts used for development.

Remove development accounts from production DBA OS group membership.

Recommend establishing a dedicated DBMS host for production DBMS installations. A dedicated host system in this case refers to an instance of the operating system at a minimum. The operating system may reside on a virtual host machine where supported by the DBMS vendor.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21563r533088_chk'
  tag severity: 'medium'
  tag gid: 'V-219852'
  tag rid: 'SV-219852r401224_rule'
  tag stig_id: 'O121-BP-024100'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21562r533089_fix'
  tag 'documentable'
  tag legacy: ['SV-75977', 'V-61487']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
