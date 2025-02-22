control 'SV-25107' do
  title 'The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.'
  desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the options must be enabled to ensure the maximum security level.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" is not set to "Require NTLMv2 session security" and "Require 128-bit encryption", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

Value Name:  NTLMMinClientSec

Value Type:  REG_DWORD
Value:  0x20080000 (537395200)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security", "Require 128-bit encryption" (all options selected).'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62075r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3382'
  tag rid: 'SV-25107r2_rule'
  tag gtitle: 'Session Security for NTLM SSP Based Clients'
  tag fix_id: 'F-66973r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
