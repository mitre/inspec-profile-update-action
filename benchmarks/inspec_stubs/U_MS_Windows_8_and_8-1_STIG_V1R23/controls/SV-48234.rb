control 'SV-48234' do
  title 'Users must not be presented with Privacy and Installation options on first use of Windows Media Player.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from being presented with Privacy and Installation options on first use of Windows Media Player which could enable some communication with the vendor.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name: GroupPrivacyAcceptance

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Do Not Show First Use Dialog Boxes" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44913r1_chk'
  tag severity: 'low'
  tag gid: 'V-15687'
  tag rid: 'SV-48234r1_rule'
  tag stig_id: 'WN08-CC-000121'
  tag gtitle: 'Media Player – First Use Dialog Boxes'
  tag fix_id: 'F-41370r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
