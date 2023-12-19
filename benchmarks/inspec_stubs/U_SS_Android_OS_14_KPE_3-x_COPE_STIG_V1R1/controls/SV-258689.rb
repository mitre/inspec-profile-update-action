control 'SV-258689' do
  title "Samsung Android's Work profile must be configured to enable Common Criteria (CC) mode."
  desc 'The CC mode feature is a superset of other features and behavioral changes that are mandatory MDFPP requirements. If CC mode is not implemented, the device will not be operating in the NIAP-certified compliant CC mode of operation.

When enforcing Android Enterprise (AE) CC mode on a Samsung Android device, additional Samsung-specific security features are also enabled.

CC mode implements the following behavioral/functional changes to meet MDFPP requirements:
- How the Bluetooth and Wi-Fi keys are stored using different types of encryption.
- Download mode is disabled and all updates will occur via Firmware Over the Air (FOTA) only.

In addition, CC mode adds new restrictions not to meet MDFPP requirements but to offer better security above what is required:
- Force password info following FOTA update for consistency.
- Disable Remote unlock by FindMyMobile.
- Restrict biometric attempts to 10.

SFR ID: FMT_MOF_EXT.1.2 #47'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are enabling CC mode.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the Work profile restrictions, verify "Common Criteria mode" is set to "Enable".

On the Samsung Android device, put the device into "Download mode" (press and hold down the Home + Power + Volume Down buttons at the same time) and verify the text "Blocked by CC Mode" is displayed on the screen.

If on the management tool "Common Criteria mode" is not set to "Enable", or on the Samsung Android device the text "Blocked by CC Mode" is not displayed in "Download mode", this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enable CC mode.

On the management tool, in the Work profile restrictions, set "Common Criteria mode" to "Enable".'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COPE'
  tag check_id: 'C-62429r931265_chk'
  tag severity: 'low'
  tag gid: 'V-258689'
  tag rid: 'SV-258689r931267_rule'
  tag stig_id: 'KNOX-14-210280'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62338r931266_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
