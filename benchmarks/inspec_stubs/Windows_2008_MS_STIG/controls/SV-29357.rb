control 'SV-29357' do
  title 'The system is not configured to meet the minimum requirement for session security for NTLM SSP based Servers.'
  desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions.  In a homogenous Windows environment, all of the options should be enabled and testing should be performed in a heterogeneous environment to determine the maximum-security level that provides reliable functionality.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.  
Navigate to Local Policies -> Security Options.

If the value for “Network security: Minimum session security for NTLM SSP based (including secure RPC) servers” is not set to “Require NTLMv2 session security” and “Require 128-bit encryption”, then this is a finding.

Warning: Microsoft warns that setting these may prevent the client from communicating with legacy servers that do not support them.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

Value Name:  NTLMMinServerSec

Value Type:  REG_DWORD
Value:  0x20080000 (537395200)

Warning: “Require NTLMv2 session security” will prevent authentication, if the “Network security: LAN Manager Authentication level” is set to permit NTLM or LM authentication. 

Documentable Explanation: If the required settings must be modified to support operation in a mixed Windows environment, then this should be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: Minimum session security for NTLM SSP based (including secure RPC) servers” to “Require NTLMv2 session security”, ”Require 128-bit encryption (all options selected).'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32752r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3666'
  tag rid: 'SV-29357r1_rule'
  tag gtitle: 'Session Security for NTLM SSP based Servers'
  tag fix_id: 'F-28830r1_fix'
  tag potential_impacts: 'Microsoft warns that setting these may prevent the server from communicating with legacy clients that do not support them.
“Require NTLMv2 session security” will prevent authentication, if the “Network security: LAN Manager authentication level” is set to permit NTLM or LM authentication.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
