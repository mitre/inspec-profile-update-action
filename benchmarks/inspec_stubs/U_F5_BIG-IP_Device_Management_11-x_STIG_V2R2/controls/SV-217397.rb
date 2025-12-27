control 'SV-217397' do
  title 'The BIG-IP appliance must be configured to ensure administrators are authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'To assure individual accountability and prevent unauthorized access, administrators must be individually identified and authenticated. 

Individual accountability mandates that each administrator is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the network device using a single account. 

If a device allows or provides for group authenticators, it must first individually authenticate administrators prior to implementing group authenticator functionality. 

Some devices may not have the need to provide a group authenticator; this is considered a matter of device design. In those instances where the device design includes the use of a group authenticator, this requirement will apply. This requirement applies to accounts created and managed on or by the network device.'
  desc 'check', 'Verify the BIG-IP appliance is configured to authenticate administrators with an individual authenticator prior to using a group authenticator. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that authenticates administrators to an administrators group.

Navigate to System >> Users >> Remote Role Groups.

Verify that administrators are assigned to the Administrator Role.

If the BIG-IP appliance is not configured to authenticate administrators with an individual authenticator prior to using a group authenticator, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to authenticate administrators with an individual authenticator prior to using a group authenticator.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18622r290745_chk'
  tag severity: 'medium'
  tag gid: 'V-217397'
  tag rid: 'SV-217397r879594_rule'
  tag stig_id: 'F5BI-DM-000101'
  tag gtitle: 'SRG-APP-000153-NDM-000249'
  tag fix_id: 'F-18620r290746_fix'
  tag 'documentable'
  tag legacy: ['SV-74575', 'V-60145']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
