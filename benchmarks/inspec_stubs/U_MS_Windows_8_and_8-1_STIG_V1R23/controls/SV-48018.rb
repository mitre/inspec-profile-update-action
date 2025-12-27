control 'SV-48018' do
  title 'The shutdown option must be available from the logon dialog box.'
  desc 'Preventing display of the shutdown button in the logon dialog box may encourage a hard shut down with the power button.  (However, displaying the shutdown button may allow individuals to shut down a system anonymously.)'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options. 

If the value for "Shutdown: Allow system to be shutdown without having to log on" is not set to "Enabled", this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ShutdownWithoutLogon

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Shutdown: Allow system to be shutdown without having to log on" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44756r1_chk'
  tag severity: 'low'
  tag gid: 'V-1075'
  tag rid: 'SV-48018r1_rule'
  tag stig_id: 'WN08-SO-000073'
  tag gtitle: 'Display Shutdown Button'
  tag fix_id: 'F-41156r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
