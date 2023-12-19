control 'SV-254478' do
  title 'Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.'
  desc 'Microsoft has implemented a variety of security support providers for use with Remote Procedure Call (RPC) sessions. All of the options must be enabled to ensure the maximum security level.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

Value Name: NTLMMinServerSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: Minimum session security for NTLM SSP based (including secure RPC) servers to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57963r849248_chk'
  tag severity: 'medium'
  tag gid: 'V-254478'
  tag rid: 'SV-254478r849250_rule'
  tag stig_id: 'WN22-SO-000340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57914r849249_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
