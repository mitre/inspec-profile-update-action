control 'SV-235824' do
  title 'Docker Enterprise secret management commands must be used for managing secrets in a Swarm cluster.'
  desc "Use Docker's in-built secret management commands for managing sensitive data that which can be stored in key/value pairs. Examples include API tokens, database connection strings and credentials, SSL certificates, and the like."
  desc 'check', "Ensure Docker's secret management commands are used for managing secrets in a Swarm cluster.

Refer to the System Security Plan (SSP) and verify that it includes documented processes for using Docker secrets commands to manage sensitive data that can be stored in key/value pairs. Examples include API tokens, database connection strings and credentials, SSL certificates, and the like.

If the SSP does not have this documented, then this is a finding."
  desc 'fix', 'Update the SSP so that it includes documented processes for using Docker secrets commands to manage sensitive data that can be stored in key/value pairs. Examples include API tokens, database connection strings and credentials, SSL certificates, and the like. Follow docker secret documentation and use it to manage secrets effectively. This documentation can be found at https://docs.docker.com/engine/swarm/secrets/.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39043r627597_chk'
  tag severity: 'medium'
  tag gid: 'V-235824'
  tag rid: 'SV-235824r627599_rule'
  tag stig_id: 'DKER-EE-002410'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-39006r627598_fix'
  tag 'documentable'
  tag legacy: ['SV-104819', 'V-95681']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
