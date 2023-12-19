control 'SV-225330' do
  title 'An Error Report must not be sent when a generic device driver is installed.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents an error report from being sent when a generic device driver is installed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: DisableSendGenericDriverNotFoundToWER

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Do not send a Windows error report when a generic driver is installed on a device" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27029r471332_chk'
  tag severity: 'low'
  tag gid: 'V-225330'
  tag rid: 'SV-225330r569185_rule'
  tag stig_id: 'WN12-CC-000020'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27017r471333_fix'
  tag 'documentable'
  tag legacy: ['V-15702', 'SV-53105']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
