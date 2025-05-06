control 'SV-25111' do
  title 'The system allows shutdown from the logon dialog box.'
  desc 'Preventing display of the shutdown button in the logon dialog box may encourage a hard shut down with the power button.  (However, displaying the shutdown button may allow individuals to shut down a system anonymously.)'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options. 

If the value for “Shutdown: Allow shutdown without having to log on” is not set to “Enabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  ShutdownWithoutLogon

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Shutdown: Allow system to be shutdown without having to log on” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-18076r1_chk'
  tag severity: 'low'
  tag gid: 'V-1075'
  tag rid: 'SV-25111r1_rule'
  tag gtitle: 'Display Shutdown Button'
  tag fix_id: 'F-17274r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
