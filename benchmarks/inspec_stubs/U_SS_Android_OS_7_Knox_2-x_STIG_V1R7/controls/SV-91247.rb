control 'SV-91247' do
  title 'The Samsung Android 7 with Knox must be configured to display the DoD advisory warning message at start-up or each time the user unlocks the device.'
  desc %q(The Samsung Android 7 with Knox is required to display the DoD-approved system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. Required banners help ensure that DoD can audit and monitor the activities of mobile device users without legal restriction.

System use notification messages can be displayed when individuals first access or unlock the mobile device. The banner shall be implemented as a "click-through" banner at device unlock (to the extent permitted by the operating system). A "click through" banner prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating “OK.”

The approved DoD text must be used exactly as required in the KS referenced in DoDI 8500.01. For devices accommodating banners of 1300 characters, the banner text is: 

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

For devices with severe character limitations, the banner text is: 

I've read & consent to terms in IS user agreem't.

The administrator must configure the banner text exactly as written without any changes.

SFR ID: FMT_SMF_EXT.1.1 #36)
  desc 'check', 'Review Samsung Android 7 with Knox documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Banner Text" field in the "DoD Banner" settings in the "Android Security" rule. 
2. Verify the correct DoD-specified warning text is displayed in the Banner Text field or the field is blank.
3. Ask the MDM administrator to display the enable checkbox in the "DoD Banner" settings in the "Android Security" rule.
4. Verify the checkbox is selected. 

On the Samsung Android 7 with Knox device, do the following:
1. Reboot the device.
2. Verify the device displays the DoD banner.
3. Verify the DoD banner is set to one of the authorized messages.

If the MDM console "DoD Banner" enable checkbox is not selected, or the "Banner Text" is not set to the appropriate designated wording or the Samsung Android 7 with Knox device does not display a warning banner with the appropriate designated wording when rebooted, this is a finding.

Note: If enabled without configuring the "Banner Text", the device will display a default text which matches the required DoD banner.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to display the DoD-mandated warning banner text.

On the MDM console, do the following:
1. Enter the correct text in the "Banner Text" field in the "DoD Banner" settings in the "Android Security" rule.
2. Select the enable checkbox in the "DoD Banner" settings in the "Android Security" rule. 

Note: If enabled without configuring the "Banner Text", the device will display a default text which matches the required DoD banner.

Note: On some MDM vendor consoles, the logon banner automatically is displayed upon reboot while the device is MDM enrolled. On these consoles, this control is not configurable through the MDM server or on the device.'
  impact 0.3
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76211r1_chk'
  tag severity: 'low'
  tag gid: 'V-76551'
  tag rid: 'SV-91247r1_rule'
  tag stig_id: 'KNOX-07-004300'
  tag gtitle: 'PP-MDF-301200'
  tag fix_id: 'F-83233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
