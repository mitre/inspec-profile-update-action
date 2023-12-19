control 'SV-205916' do
  title 'Windows Server 2019 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.'
  desc 'Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\

Value Name: UseMachineId

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow Local System to use computer identity for NTLM" to "Enabled".'
  impact 0.5
  ref 'DPMS Target MS Windows Server 2019'
  tag check_id: 'C-6181r356110_chk'
  tag severity: 'medium'
  tag gid: 'V-205916'
  tag rid: 'SV-205916r569188_rule'
  tag stig_id: 'WN19-SO-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-6181r356111_fix'
  tag 'documentable'
  tag legacy: ['SV-103383', 'V-93295']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
