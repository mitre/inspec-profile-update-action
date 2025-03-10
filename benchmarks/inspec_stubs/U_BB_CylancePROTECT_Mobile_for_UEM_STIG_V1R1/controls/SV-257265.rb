control 'SV-257265' do
  title 'CylancePROTECT Mobile must be configured with the following compliance actions when insecure networks are detected for mobile devices:
-Block device from network connection and insecure Wi-Fi access points.
-Block access to BlackBerry Dynamics apps.'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance actions are enabled when insecure networks are detected:
-Block device from network connection and insecure Wi-Fi access points.
-Block access to BlackBerry Dynamics apps.

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Open the appropriate compliance profile (have the site system administrator identify the profile).
4. Verify required compliance actions for insecure network detection are enabled.
a. On both the iOS and Android tabs, in the BlackBerry Protect section, verify "Insecure network detected" is selected.
b. In the "Prompt for compliance" drop-down list, verify "Immediate enforcement action" is selected.
c. In the "Enforcement action for device" drop-down list, verify "Untrust" is selected (Android only).
d. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, verify "Do not allow BlackBerry Dynamics apps to run" is selected.
5. Verify compliance actions for insecure Wi-Fi access point detection are enabled (Android only).
a. On the Android tab in the BlackBerry Protect section, verify "Insecure Wi-Fi network detected" is selected.
b. In the "Prompt for compliance" drop-down list, verify "Immediate enforcement action" is selected.
c. In the "Enforcement action for device" drop-down list, verify "Untrust" is selected. 
d. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, verify "Do not allow BlackBerry Dynamics apps to run" is selected.

If any required compliance actions for insecure network detection for mobile devices has not been implemented, this is a finding.'
  desc 'fix', 'Configure the following compliance actions when insecure networks are detected:
-Block device from network connection and insecure Wi-Fi access points.
-Block access to BlackBerry Dynamics apps.

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Create a new compliance profile or select and edit an existing compliance profile.
4. Configure compliance actions for insecure network detection.
a. On both the iOS and Android tabs, in the BlackBerry Protect section, select the "Insecure network detected" check box.
b. Configure the behavior prompt settings: Prompt for compliance: "Immediate enforcement action".
c. In the "Enforcement action for device" drop-down list, select the following: "Untrust" (Android only).
d. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, select the following: "Do not allow BlackBerry Dynamics apps to run".
5. Configure compliance actions for insecure Wi-Fi access point detection (Android only).
a. On the Android tab in the BlackBerry Protect section, select the "Insecure Wi-Fi network detected" check box.
b. Configure the behavior prompt settings: Prompt for compliance: "Immediate enforcement action".
c. In the "Enforcement action for device" drop-down list, select the following: "Untrust".
d. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, select the following: "Do not allow BlackBerry Dynamics apps to run".
6. Click "Save".
7. Assign the profile to users.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60949r918377_chk'
  tag severity: 'medium'
  tag gid: 'V-257265'
  tag rid: 'SV-257265r918379_rule'
  tag stig_id: 'BBCP-00-013100'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60891r918378_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
