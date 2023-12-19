control 'SV-88361' do
  title 'Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.'
  desc 'Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

Value Name: NTLMMinServerSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73697'
  tag rid: 'SV-88361r1_rule'
  tag stig_id: 'WN16-SO-000410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-80147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
