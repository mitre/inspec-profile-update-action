control 'SV-234366' do
  title 'The UEM server must disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 

Applications need to track periods of inactivity and disable application identifiers after 35 days of inactivity. 

Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.

To avoid having to build complex user management capabilities directly into their application, wise developers leverage the underlying OS or other user account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements.'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server disables identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.

If the UEM server does not disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Configure the UEM server to disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37551r614108_chk'
  tag severity: 'medium'
  tag gid: 'V-234366'
  tag rid: 'SV-234366r617355_rule'
  tag stig_id: 'SRG-APP-000163-UEM-000093'
  tag gtitle: 'SRG-APP-000163'
  tag fix_id: 'F-37516r614109_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
