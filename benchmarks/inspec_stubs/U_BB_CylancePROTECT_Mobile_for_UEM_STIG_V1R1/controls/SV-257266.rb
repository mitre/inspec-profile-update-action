control 'SV-257266' do
  title 'CylancePROTECT Mobile must be configured with the following compliance actions for integrity violations with BlackBerry Dynamics apps on iOS devices:
-Prompt for compliance: Immediate enforcement action
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance actions for BlackBerry Dynamics apps are configured when there is an iOS device integrity violation:
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. View the appropriate compliance profile (have the site system administrator identify the profile).
4. On the iOS tab in the BlackBerry Protect section, verify the "App integrity failed" check box is selected.
5. In the "Prompt for compliance" drop-down list verify "Immediate enforcement action" is selected 
6. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, verify  "Do not allow BlackBerry Dynamics apps to run" is selected.

If required compliance actions for integrity violations for BlackBerry Dynamics apps on iOS devices are not enabled, this is a finding.'
  desc 'fix', 'Configure the following compliance actions for iOS device integrity violations for BlackBerry Dynamics apps:
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Create a new compliance profile or select and edit an existing compliance profile.
4. On the iOS tab in the BlackBerry Protect section, select the "App integrity failed" check box.
5. Configure the behavior prompt settings: Prompt for compliance: "Immediate enforcement action".
6. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, choose the following: "Do not allow BlackBerry Dynamics apps to run".
7. Click "Add" or "Save".
8. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60950r918380_chk'
  tag severity: 'medium'
  tag gid: 'V-257266'
  tag rid: 'SV-257266r918382_rule'
  tag stig_id: 'BBCP-00-013200'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60892r918381_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
