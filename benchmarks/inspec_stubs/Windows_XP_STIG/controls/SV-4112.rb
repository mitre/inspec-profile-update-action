control 'SV-4112' do
  title 'The system is configured to detect and configure default gateway addresses.'
  desc 'Enables or disables the Internet Router Discovery Protocol (IRDP) used to detect and configure Default Gateway addresses on the computer.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-4112'
  tag rid: 'SV-4112r1_rule'
  tag gtitle: 'Disable Router Discovery'
  tag fix_id: 'F-5730r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
