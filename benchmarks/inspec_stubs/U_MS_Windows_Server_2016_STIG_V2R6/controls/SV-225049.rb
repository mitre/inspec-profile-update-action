control 'SV-225049' do
  title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.'
  desc 'Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously versus using the computer identity.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\

Value Name: UseMachineId

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow Local System to use computer identity for NTLM" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26740r466049_chk'
  tag severity: 'medium'
  tag gid: 'V-225049'
  tag rid: 'SV-225049r569186_rule'
  tag stig_id: 'WN16-SO-000320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26728r466050_fix'
  tag 'documentable'
  tag legacy: ['SV-88343', 'V-73679']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
