control 'SV-7072' do
  title 'Outgoing secure channel traffic is not encrypted or signed.'
  desc 'Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic will be encrypted and signed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Digitally encrypt or sign secure channel data (always)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-6831'
  tag rid: 'SV-7072r1_rule'
  tag gtitle: 'Encrypting and Signing of Secure Channel Traffic'
  tag fix_id: 'F-6518r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCT-2, ECCT-1'
end
