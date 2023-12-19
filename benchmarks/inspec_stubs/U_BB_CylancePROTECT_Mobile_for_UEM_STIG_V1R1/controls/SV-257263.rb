control 'SV-257263' do
  title 'CylancePROTECT Mobile must be configured with the following compliance actions when sideloaded apps are detected:
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing work resources and apps on the device while it is out of compliance.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance actions have been enabled when sideloaded apps are detected:
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing work resources and apps on the device while it is out of compliance.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Find the CylancePROTECT Mobile sideloaded app compliance profile (have the site system administrator identify the correct profile).
4. Select the iOS tab and verify the following selections:
5. In the "Prompt for compliance" drop-down list verify "Immediate enforcement action" is selected.
6. In the "Enforcement action for device" drop-down list, verify  "Untrust" is selected.
7. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, verify "Do not allow BlackBerry Dynamics apps to run" is selected.
8. Repeat steps 4–6 for Android.

If required compliance actions for when sideloaded apps are detected for iOS and Android are not configured, this is a finding.'
  desc 'fix', 'Configure the following compliance actions when sideloaded apps are detected:
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing work resources and apps on the device while it is out of compliance.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Create a new compliance profile or select and edit an existing compliance profile.
4. Select the iOS tab to configure sideload detection for that platform.
5. In the BlackBerry Protect section, select the "Sideloaded app is installed" check box.
6. Configure the behavior prompt settings: Prompt for compliance: "Immediate enforcement action".
7. In the "Enforcement action for device" drop-down list, select "Untrust".
8. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, select "Do not allow BlackBerry Dynamics apps to run".
9. Repeat steps 3–7 for configure compliance actions for Android.
10. Click "Save".
11. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60947r918371_chk'
  tag severity: 'medium'
  tag gid: 'V-257263'
  tag rid: 'SV-257263r918373_rule'
  tag stig_id: 'BBCP-00-012900'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60889r918372_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
