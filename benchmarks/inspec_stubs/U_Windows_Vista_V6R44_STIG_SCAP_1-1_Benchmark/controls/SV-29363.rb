control 'SV-29363' do
  title 'The system is configured to redirect ICMP.'
  desc 'When disabled, forces ICMP to be routed via shortest path first.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-4111'
  tag rid: 'SV-29363r1_rule'
  tag gtitle: 'Disable ICMP Redirect'
  tag fix_id: 'F-5715r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
