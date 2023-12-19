control 'SV-225056' do
  title 'Session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption.'
  desc 'Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

Value Name: NTLMMinClientSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26747r466070_chk'
  tag severity: 'medium'
  tag gid: 'V-225056'
  tag rid: 'SV-225056r569186_rule'
  tag stig_id: 'WN16-SO-000400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26735r466071_fix'
  tag 'documentable'
  tag legacy: ['SV-88359', 'V-73695']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
