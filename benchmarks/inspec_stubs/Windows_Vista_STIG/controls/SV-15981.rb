control 'SV-15981' do
  title 'The system is not configured to meet the minimum requirement for session security for NTLM SSP based Servers.'
  desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions.  In a homogenous Windows environment, all of the options should be enabled and testing should be performed in a heterogeneous environment to determine the maximum-security level that provides reliable functionality.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: Minimum session security for NTLM SSP based (including secure RPC) servers” to “Require NTLMv2 session security”, ”Require 128-bit encryption (all options selected).'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3666'
  tag rid: 'SV-15981r1_rule'
  tag gtitle: 'Session Security for NTLM SSP based Servers'
  tag fix_id: 'F-28830r1_fix'
  tag potential_impacts: 'Microsoft warns that setting these may prevent the server from communicating with legacy clients that do not support them.
“Require NTLMv2 session security” will prevent authentication, if the “Network security: LAN Manager authentication level” is set to permit NTLM or LM authentication.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
