control 'SV-226332' do
  title 'The system must be configured to meet the minimum session security requirement for NTLM SSP-based clients.'
  desc 'Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the options must be enabled to ensure the maximum security level.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

Value Name: NTLMMinClientSec

Value Type: REG_DWORD
Value: 0x20080000 (537395200)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options selected).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28034r476840_chk'
  tag severity: 'medium'
  tag gid: 'V-226332'
  tag rid: 'SV-226332r794678_rule'
  tag stig_id: 'WN12-SO-000069'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-28022r476841_fix'
  tag 'documentable'
  tag legacy: ['SV-52895', 'V-3382']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
