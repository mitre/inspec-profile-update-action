control 'SV-32280' do
  title 'The shutdown option will not be available from the logon dialog box.'
  desc 'Displaying the shutdown button may allow individuals to shut down a system anonymously.  Only authenticated users should be allowed to shut down the system.  Preventing display of this button in the logon dialog box ensures that individuals who shut down the system are authorized and tracked in the systems Security event log.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “Shutdown: Allow system to be shutdown without having to log on” is not set to “Disabled”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name:  ShutdownWithoutLogon

Value Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Shutdown: Allow system to be shutdown without having to log on” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32716r1_chk'
  tag severity: 'low'
  tag gid: 'V-1075'
  tag rid: 'SV-32280r1_rule'
  tag gtitle: 'Display Shutdown Button'
  tag fix_id: 'F-28803r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
