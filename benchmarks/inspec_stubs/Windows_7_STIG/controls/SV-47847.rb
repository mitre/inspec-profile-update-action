control 'SV-47847' do
  title 'Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.'
  desc 'A compromised local administrator account can provide means for an attacker to move laterally between domain systems. 

With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.'
  desc 'check', 'If the system is not a member of a domain, this is NA. 
If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: LocalAccountTokenFilterPolicy

Type: REG_DWORD
Value: 0x00000000 (0)

This setting may cause issues with some network scanning tools if local administrative accounts are used remotely.  Scans should use domain accounts where possible.  If a local administrative account must be used, temporarily enabling the privileged token by configuring the registry value to 1 may be required.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Apply UAC restrictions to local accounts on network logons" to "Enabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-44683r7_chk'
  tag severity: 'medium'
  tag gid: 'V-36439'
  tag rid: 'SV-47847r2_rule'
  tag stig_id: 'WINRG-000003'
  tag gtitle: 'Local admin accounts filtered token policy enabled on domain systems.'
  tag fix_id: 'F-80975r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
