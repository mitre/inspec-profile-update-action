control 'SV-204750' do
  title 'The application server must disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 

Applications need to track periods of inactivity and disable application identifiers after 35 days of inactivity. 

Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.

To avoid having to build complex user management capabilities directly into their application, wise developers leverage the underlying OS or other user account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements.'
  desc 'check', 'Review the application server documentation and configuration to ensure the application server disables identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.

If the application server is not configured to disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity, this is a finding.'
  desc 'fix', 'Configure the application server to disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4870r282897_chk'
  tag severity: 'medium'
  tag gid: 'V-204750'
  tag rid: 'SV-204750r879600_rule'
  tag stig_id: 'SRG-APP-000163-AS-000111'
  tag gtitle: 'SRG-APP-000163'
  tag fix_id: 'F-4870r282898_fix'
  tag 'documentable'
  tag legacy: ['SV-46596', 'V-35309']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
