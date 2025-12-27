control 'SV-48128' do
  title 'The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.'
  desc 'Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log onto the system before the lock takes effect.'
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" is not set to "5" or less, this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: ScreenSaverGracePeriod

Value Type: REG_SZ
Value: 5 (or less))
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" to "5" or less.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44854r1_chk'
  tag severity: 'low'
  tag gid: 'V-4442'
  tag rid: 'SV-48128r1_rule'
  tag stig_id: 'WN08-SO-000046'
  tag gtitle: 'Screen Saver Grace Period'
  tag fix_id: 'F-41265r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
