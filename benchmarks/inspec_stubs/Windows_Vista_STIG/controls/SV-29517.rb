control 'SV-29517' do
  title 'Outgoing secure channel traffic is not signed when possible.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but the channel is not integrity checked.  If this policy is enabled, all outgoing secure channel traffic should be signed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Digitally sign secure channel data (when possible)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-1164'
  tag rid: 'SV-29517r1_rule'
  tag gtitle: 'Signing of Secure Channel Traffic'
  tag fix_id: 'F-100r1_fix'
  tag false_positives: 'If the value for “Domain Member: Digitally encrypt or sign secure channel data (always)” is set to “Enabled”, then this would not be a finding.'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002418', 'CCI-002421']
  tag nist: ['SC-8', 'SC-8 (1)']
end
