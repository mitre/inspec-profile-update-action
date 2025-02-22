control 'SV-226214' do
  title 'Users must not be presented with Privacy and Installation options on first use of Windows Media Player.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from being presented with Privacy and Installation options on first use of Windows Media Player, which could enable some communication with the vendor.'
  desc 'check', 'Windows Media Player is not installed by default.  If it is not installed, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name: GroupPrivacyAcceptance

Type: REG_DWORD
Value: 1'
  desc 'fix', 'If Windows Media Player is installed, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Do Not Show First Use Dialog Boxes" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27916r475965_chk'
  tag severity: 'low'
  tag gid: 'V-226214'
  tag rid: 'SV-226214r794506_rule'
  tag stig_id: 'WN12-CC-000121'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27904r475966_fix'
  tag 'documentable'
  tag legacy: ['SV-53069', 'V-15687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
