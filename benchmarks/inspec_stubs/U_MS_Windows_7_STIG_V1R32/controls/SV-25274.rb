control 'SV-25274' do
  title 'Services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity vs. authenticating anonymously.'
  desc 'Services using Local System that use Negotiate when reverting to NTLM authentication may gain unauthorized access if allowed to authenticate anonymously instead of using the computer identity.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network Security: Allow Local System to use computer identity for NTLM" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SYSTEM\\CurrentControlSet\\Control\\LSA\\

Value Name:  UseMachineId

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network Security: Allow Local System to use computer identity for NTLM" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60809r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21951'
  tag rid: 'SV-25274r2_rule'
  tag gtitle: 'Computer Identity Authentication for NTLM'
  tag fix_id: 'F-65541r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
