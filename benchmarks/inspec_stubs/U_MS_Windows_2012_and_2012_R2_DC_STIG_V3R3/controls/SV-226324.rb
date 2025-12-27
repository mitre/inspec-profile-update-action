control 'SV-226324' do
  title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'
  desc 'Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously vs. using the computer identity.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\

Value Name: UseMachineId

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow Local System to use computer identity for NTLM" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28026r476816_chk'
  tag severity: 'medium'
  tag gid: 'V-226324'
  tag rid: 'SV-226324r794537_rule'
  tag stig_id: 'WN12-SO-000061'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-28014r476817_fix'
  tag 'documentable'
  tag legacy: ['SV-53176', 'V-21951']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
