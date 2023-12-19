control 'SV-29360' do
  title 'The system is configured to allow IP source routing.'
  desc 'Protects against IP source routing spoofing.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)” to “Highest protection, source routing is completely disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-4110'
  tag rid: 'SV-29360r1_rule'
  tag gtitle: 'Disable IP Source Routing'
  tag fix_id: 'F-5713r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
