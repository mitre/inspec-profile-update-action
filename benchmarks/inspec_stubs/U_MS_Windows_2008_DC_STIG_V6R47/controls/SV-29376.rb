control 'SV-29376' do
  title 'This check verifies that Windows is configured to have password protection take effect within a limited time frame when the screen saver becomes active.'
  desc 'Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log onto the system before the lock takes effect.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)” is not set to “5” or less, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  ScreenSaverGracePeriod

Value Type:  REG_SZ
Value:  5 (or less)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)” to “5” or less.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32758r1_chk'
  tag severity: 'low'
  tag gid: 'V-4442'
  tag rid: 'SV-29376r1_rule'
  tag gtitle: 'Screen Saver Grace Period'
  tag fix_id: 'F-28833r1_fix'
  tag false_negatives: 'An issue was identified where the Security Options files and analysis templates included the registry value for this setting as a Dword type however it should have been a String value. This has been reported to Microsoft and the Security Options files and analysis templates included with the checklists have been corrected as of the December 2008 release.'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
