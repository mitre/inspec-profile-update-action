control 'SV-29735' do
  title 'Software certificate restriction policies are not enforced.'
  desc 'Software restriction policies help to protect users and computers from executing unauthorized code such as viruses and Trojans horses.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “System Settings: Use Certificate Rules on Windows Executables for Software Restriction Policies” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\

Value Name:  AuthenticodeEnabled

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “System Settings: Use Certificate Rules on Windows Executables for Software Restriction Policies” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-350r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4446'
  tag rid: 'SV-29735r1_rule'
  tag gtitle: 'Software Restriction Policies'
  tag fix_id: 'F-5742r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
