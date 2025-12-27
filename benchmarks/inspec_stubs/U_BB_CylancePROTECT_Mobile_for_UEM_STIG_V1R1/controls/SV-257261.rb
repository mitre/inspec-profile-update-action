control 'SV-257261' do
  title 'CylancePROTECT Mobile malware detection must be configured with the following compliance actions for nonsystem apps (Android only):
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing work resources and apps on the device while it is out of compliance.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance actions are enabled when malware is detected for nonsystem apps (Android only):
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing work resources and apps on the device while it is out of compliance.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.

1. Log on to the BlackBerry UEM console.
2. Select Policies and profiles >> Compliance >> Compliance.
3. Select a compliance profile to review.
4. On the Android tab in the BlackBerry Protect section, verify:
a. The "Malicious app package detected" box is selected.
b. In the Prompt for compliance box, verify "Immediate enforcement action" is selected.
c. In the "Enforcement action for device" drop-down list, verify "Untrust" is selected.
d. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, verify "Do not allow BlackBerry Dynamics apps to run" is selected.

If required compliance actions when malware is detected for nonsystem apps are not configured, this is a finding.'
  desc 'fix', 'Configure the following compliance actions when malware is detected for nonsystem apps (Android only):
-Prompt for compliance: Immediate enforcement action.
-Prevent the user from accessing work resources and apps on the device while it is out of compliance.
-Prevent the user from accessing BlackBerry Dynamics apps while the device is out of compliance.

1. Log on to the BlackBerry UEM console.
2. Select Policies and profiles >> Compliance >> Compliance.
3. Create a new compliance profile or select and edit an existing compliance profile.
4. On the Android tab in the BlackBerry Protect section, do the following:
a. Select the "Malicious app package detected" check box.
b. Configure the behavior prompt settings: Prompt for compliance: "Immediate enforcement action".
c. In the "Enforcement action for device" drop-down list, select "Untrust" (work resources and apps cannot be accessed).
d. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, select "Do not allow BlackBerry Dynamics apps to run".
5. Click "Save".
6. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60945r918365_chk'
  tag severity: 'medium'
  tag gid: 'V-257261'
  tag rid: 'SV-257261r918367_rule'
  tag stig_id: 'BBCP-00-012700'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60887r918366_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
