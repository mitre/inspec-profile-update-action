control 'SV-231043' do
  title 'Samsung Android must be configured to enable Knox CC Mode.'
  desc 'The KPE CC Mode feature is a superset of other features and behavioral changes that are mandatory MDFPP requirements. If CC mode is not implemented the device will not be operating in the NIAP-certified compliant CC Mode of operation.

CC Mode implements the following behavioral/functional changes to meet MDFPP requirements:
- Download Mode is disabled and all updates will occur via FOTA only.

In addition, CC Mode adds new restrictions, which are not to meet MDFPP requirements, but to offer better security above what is required:
- Force password info following FOTA update for consistency.
- Disable Remote unlock by FindMyMobile.
- Restrict biometric attempts to 10 for better security.
- Support Android CommonCriteria mode API implementation which secures BT and Wi-Fi keys.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android configuration settings to determine if KPE CC Mode is enabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "CC mode" is set to "Enable".

On the Samsung Android device, put the device into "Download mode" and verify that the text "Blocked by CC Mode" is displayed on the screen.

If on the management tool "CC mode" is not set to "Enable", or on the Samsung Android device the text "Blocked by CC Mode" is not displayed in "Download mode", this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable KPE CC Mode.

On the management tool, in the device restrictions section, set "CC mode" to "Enable".'
  impact 0.3
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33973r592743_chk'
  tag severity: 'low'
  tag gid: 'V-231043'
  tag rid: 'SV-231043r608683_rule'
  tag stig_id: 'KNOX-11-020200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-33946r592744_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
