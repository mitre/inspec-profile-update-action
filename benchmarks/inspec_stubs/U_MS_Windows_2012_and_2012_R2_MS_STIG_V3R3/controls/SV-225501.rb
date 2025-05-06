control 'SV-225501' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27200r471845_chk'
  tag severity: 'medium'
  tag gid: 'V-225501'
  tag rid: 'SV-225501r569185_rule'
  tag stig_id: 'WN12-SO-000061'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag fix_id: 'F-27188r471846_fix'
  tag 'documentable'
  tag legacy: ['V-21951', 'SV-53176']
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
