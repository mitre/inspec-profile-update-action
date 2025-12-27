control 'SV-257270' do
  title 'CylancePROTECT Mobile must be configured with the following compliance actions when a hardware attestation certificate failure occurs (Android only):
-Minimum security level required: "Trusted Environment" or "StrongBox"
-Prompt behavior: "Immediate enforcement action".
-Enforcement action for BlackBerry Dynamics apps: "Do not allow BlackBerry Dynamics apps to run".'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance actions are enabled when a hardware attestation certificate failure occurs (Android only):
-Minimum security level required: "Trusted Environment" or "StrongBox".
-Prompt behavior: "Immediate enforcement action".
-Enforcement action for BlackBerry Dynamics apps: "Do not allow BlackBerry Dynamics apps to run".

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Select the appropriate compliance profile (have the site system admin identify the profile).
4. On the Android tab in the BlackBerry Protect section, verify "Hardware attestation security level" has been selected.
5. In the "Minimum security level required" drop-down list, verify either "Trusted Environment" or "StrongBox" is selected.
6. In the "Prompt behavior" drop-down list, verify "Immediate enforcement action" is selected.
7. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, verify "Do not allow BlackBerry Dynamics apps to run" is selected.

If required compliance actions are not enabled when a hardware attestation certificate failure occurs, this is a finding.'
  desc 'fix', 'Configure the following compliance actions when a hardware attestation certificate failure occurs (Android only):
-Minimum security level required: "Trusted Environment" or "StrongBox".
-Prompt behavior: "Immediate enforcement action".
-Enforcement action for BlackBerry Dynamics apps: "Do not allow BlackBerry Dynamics apps to run".

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Create a new compliance profile or select and edit an existing compliance profile.
4. On the Android tab in the BlackBerry Protect section, select the "Hardware attestation security level" check box.
5. In the "Minimum security level required" drop-down list, select either "Trusted Environment" or "StrongBox".
6. In the "Prompt behavior" drop-down list, select "Immediate enforcement action".
7. In the "Enforcement action for BlackBerry Dynamics apps" drop-down list, select "Do not allow BlackBerry Dynamics apps to run".
8. Click "Add" or "Save".
9. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60954r918392_chk'
  tag severity: 'medium'
  tag gid: 'V-257270'
  tag rid: 'SV-257270r918394_rule'
  tag stig_id: 'BBCP-00-013600'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60896r918393_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
