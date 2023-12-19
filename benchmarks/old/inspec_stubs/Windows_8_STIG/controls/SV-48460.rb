control 'SV-48460' do
  title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
  desc 'Unattended systems are susceptible to unauthorized use and should be locked when unattended.  The screen saver should be set at a maximum of 15 minutes and be password protected.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options. 

If the value for "Interactive logon: Machine inactivity limit" is not set to "900" seconds or less, this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Machine inactivity limit" to "900" seconds".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45124r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36773'
  tag rid: 'SV-48460r2_rule'
  tag stig_id: 'WN08-SO-000021'
  tag gtitle: 'WINSO-000021'
  tag fix_id: 'F-41587r1_fix'
  tag 'documentable'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
