control 'SV-96033' do
  title 'The Central Log Server must disable accounts (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 

Applications need to track periods of inactivity and disable application identifiers after 35 days of inactivity. 

Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.

To avoid having to build complex user management capabilities directly into their application, wise developers leverage the underlying OS or other user account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to disable accounts (individuals, groups, roles, and devices) after 35 days of inactivity.

If the Central Log Server does not disable accounts (individuals, groups, roles, and devices) after 35 days of inactivity, this is a finding.'
  desc 'fix', 'For local accounts (except for the account of last resort), configure the Central Log Server to disable accounts (individuals, groups, roles, and devices) after 35 days of inactivity.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81021r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81319'
  tag rid: 'SV-96033r1_rule'
  tag stig_id: 'SRG-APP-000163-AU-002470'
  tag gtitle: 'SRG-APP-000163-AU-002470'
  tag fix_id: 'F-88101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
