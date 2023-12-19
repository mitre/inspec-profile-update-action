control 'SV-32445' do
  title 'Services using Local System that use negotiate when reverting to NTLM authentication will use the computer identity vs. authenticating anonymously.'
  desc 'This setting ensures that services using Local System that use negotiate when reverting to NTLM authentication will use the computer identity vs. authenticating anonymously.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “Network Security: Allow Local System to use computer identity for NTLM” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\System\\CurrentControlSet\\Control\\LSA\\

Value Name:  UseMachineId

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network Security: Allow Local System to use computer identity for NTLM” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21951'
  tag rid: 'SV-32445r1_rule'
  tag gtitle: 'Computer Identity Authentication for NTLM'
  tag fix_id: 'F-28856r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
