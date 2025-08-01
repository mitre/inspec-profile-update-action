control 'SV-257268' do
  title 'CylancePROTECT Mobile must be configured with the following compliance actions when an Android device fails security patch compliance and attestation:
-Prompt behavior: Immediate enforcement action.
-Enforcement action for device: Select either "Untrust", "Delete only work data" or "Delete all data".
-Enforcement action for BlackBerry Dynamics apps: Select either "Do not allow BlackBerry Dynamics apps to run" or "Delete BlackBerry Dynamics apps data".'
  desc 'When a compliance failure is detected, compliance actions must be implemented immediately to limit exposure of sensitive data and unauthorized access to the mobile device.'
  desc 'check', 'Verify the following compliance actions when an Android device fails security patch compliance and attestation have been configured:
-Prompt behavior: Immediate enforcement action.
-Enforcement action for device: Select either "Untrust", "Delete only work data", or "Delete all data".
-Enforcement action for BlackBerry Dynamics apps: Select either "Do not allow BlackBerry Dynamics apps to run" or "Delete BlackBerry Dynamics apps data".

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Select the appropriate compliance profile (have the site system administrator identify the profile).
4. On the Android tab, verify "Required security patch level is not installed" check box has been selected.
5. Verify for "Prompt behavior" "Immediate enforcement action" has been selected.
6. Verify for "Enforcement action for device" either "Untrust", "Delete work data only", or "Delete all data" has been selected.
7. Verify for "Enforcement action for BlackBerry Dynamics apps" either "Do not allow BlackBerry Dynamics apps to run" or "Delete BlackBerry Dynamics apps data" has been selected.

If required compliance actions when an Android device fails security patch compliance and attestation have not been configured, this is a finding.'
  desc 'fix', 'Configure the following compliance actions when an Android device fails security patch compliance and attestation:
-Prompt behavior: Immediate enforcement action.
-Enforcement action for device: Select either "Untrust", "Delete only work data", or "Delete all data".
-Enforcement action for BlackBerry Dynamics apps: Select either "Do not allow BlackBerry Dynamics apps to run" or "Delete BlackBerry Dynamics apps data".

1. Log on to the BlackBerry UEM console.
2. In the management console on the menu bar, click Policies and profiles >> Compliance >> Compliance.
3. Create a new compliance profile or select and edit an existing compliance profile.
4. On the Android tab, select the "Required security patch level is not installed" check box. Add the required device models and corresponding security patches.
5. For "Prompt behavior", select "Immediate enforcement action".
6. For "Enforcement action for device" select either "Untrust", "Delete work data only", or "Delete all data".
7. For "Enforcement action for BlackBerry Dynamics apps", select either "Do not allow BlackBerry Dynamics apps to run" or "Delete BlackBerry Dynamics apps data".
8. Click "Add" or "Save".
9. Assign the profile to users and groups.'
  impact 0.5
  ref 'DPMS Target BlackBerry CylancePROTECT Mobile for UEM'
  tag check_id: 'C-60952r918386_chk'
  tag severity: 'medium'
  tag gid: 'V-257268'
  tag rid: 'SV-257268r918388_rule'
  tag stig_id: 'BBCP-00-013400'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-60894r918387_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
