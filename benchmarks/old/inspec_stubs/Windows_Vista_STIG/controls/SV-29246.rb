control 'SV-29246' do
  title 'The maximum age for machine account passwords is not set to requirements.'
  desc 'This setting controls the maximum password age that a machine account may have.  This setting should be set to no more than 30 days, ensuring the machine changes its password monthly.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Maximum Machine Account Password Age” to 30 or less, but not 0.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-3373'
  tag rid: 'SV-29246r1_rule'
  tag gtitle: 'Maximum Machine Account Password Age'
  tag fix_id: 'F-34273r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
