control 'SV-255133' do
  title 'Samsung Android must be configured to enable Common Criteria (CC) mode.'
  desc 'The CC Mode feature is a superset of other features and behavioral changes that are mandatory MDFPP requirements. If CC mode is not implemented the device will not be operating in the NIAP-certified compliant CC Mode of operation.

When enforcing AE CC mode on a Samsung Android device, additional Samsung-specific security features are also enabled.

CC Mode implements the following behavioral/functional changes to meet MDFPP requirements:
- How the Bluetooth and Wi-Fi keys are stored using different types of encryption.
- Download Mode is disabled and all updates will occur via FOTA only.

In addition, CC Mode adds new restrictions, which are not to meet MDFPP requirements, but to offer better security above what is required:
- Force password info following FOTA update for consistency.
- Disable Remote unlock by FindMyMobile.
- Restrict biometric attempts to 10 for better security.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enabling CC mode.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "Common Criteria mode" is set to "Enable".

On the Samsung Android device, put the device into "Download mode" and verify that the text "Blocked by CC Mode" is displayed on the screen.

If on the management tool "Common Criteria mode" is not set to "Enable", or on the Samsung Android device the text "Blocked by CC Mode" is not displayed in "Download mode", this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enable CC mode.

On the management tool, in the device restrictions, set "Common Criteria mode" to "Enable".'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58746r867334_chk'
  tag severity: 'low'
  tag gid: 'V-255133'
  tag rid: 'SV-255133r867336_rule'
  tag stig_id: 'KNOX-13-110280'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58690r867335_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
