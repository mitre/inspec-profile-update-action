control 'SV-3382' do
  title 'The system is not configured to meet the minimum requirement for session security for NTLM SSP based Clients.'
  desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions.  In a homogenous Windows environment, all of the options should be enabled and testing should be performed in a heterogeneous environment to determine the maximum-security level that provides reliable functionality.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: Minimum session security for NTLM SSP based (including secure RPC) clients” to “Require NTLMv2 session security”, ”Require 128-bit encryption”, ”Require Message Integrity”, and  ”Require Message Confidentiality” (all options selected).'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3382'
  tag rid: 'SV-3382r1_rule'
  tag gtitle: 'Session Security for NTLM SSP Based Clients'
  tag fix_id: 'F-145r1_fix'
  tag potential_impacts: 'Microsoft warns that setting these may prevent the client from communicating with legacy servers that do not support them.
“Require NTLMv2 session security” will prevent authentication, if the “Network security: LAN Manager authentication level” is set to permit NTLM or LM authentication.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECCT-1, ECCT-2'
end
