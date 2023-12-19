control 'SV-48241' do
  title 'An Error Report must not be sent when a generic device driver is installed.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents an error report from being sent when a generic device driver is installed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: DisableSendGenericDriverNotFoundToWER

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Do not send a Windows Error Report when a generic driver is installed on a device" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44920r1_chk'
  tag severity: 'low'
  tag gid: 'V-15702'
  tag rid: 'SV-48241r2_rule'
  tag stig_id: 'WN08-CC-000020'
  tag gtitle: 'Device Install – Generic Driver Error Report'
  tag fix_id: 'F-41377r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
