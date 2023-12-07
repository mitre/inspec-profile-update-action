control 'SV-226154' do
  title 'Windows must be prevented from sending an error report when a device driver requests additional software during installation.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent Windows from sending an error report to Microsoft when a device driver requests additional software during installation.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

Value Name: DisableSendRequestAdditionalSoftwareToWER

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Prevent Windows from sending an error report when a device driver requests additional software during installation" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27856r475785_chk'
  tag severity: 'low'
  tag gid: 'V-226154'
  tag rid: 'SV-226154r794422_rule'
  tag stig_id: 'WN12-CC-000023'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27844r475786_fix'
  tag 'documentable'
  tag legacy: ['SV-52962', 'V-28504']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
