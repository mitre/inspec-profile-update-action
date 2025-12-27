control 'SV-95091' do
  title 'Samsung Android 8 with Knox must be configured to disable developer modes.'
  desc 'Developer modes expose features of the Samsung Android 8 with Knox that are not available during standard operation. An adversary may leverage a vulnerability inherent in a developer mode to compromise the confidentiality, integrity, and availability of DoD sensitive information. Disabling developer modes mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #26'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine whether a developer mode is enabled.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Developer Mode" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Developer options". (**)
3. Attempt to enable "Developer options".

If the MDM console "Allow Developer Mode" check box is selected or on the Samsung Android 8 with Knox device, "Developer options" can be enabled by the user, this is a finding.

Note: The "Developer Modes" configuration setting may not be available in older MDM consoles. Disabling USB Debugging and Mock Locations also disables Developer modes on the mobile device.

(**) "Developer options" is initially hidden to users. To unhide this menu item:
1. Open the device settings.
2. Select "About device".
3. Select "Software info". (Note: On some devices, this step is not needed.)
4. Rapidly tap on "Build number" multiple times until the device displays the Developer Options menu item.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to disable developer modes.

On the MDM console, deselect the "Allow Developer Mode" check box in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80387'
  tag rid: 'SV-95091r1_rule'
  tag stig_id: 'KNOX-08-017900'
  tag gtitle: 'PP-MDF-301170'
  tag fix_id: 'F-87193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
