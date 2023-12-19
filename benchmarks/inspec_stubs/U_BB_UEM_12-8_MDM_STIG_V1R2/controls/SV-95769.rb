control 'SV-95769' do
  title 'The BlackBerry UEM 12.8 server must configure the MDM Agent/platform to enable the DoD required device enrollment restrictions allowed for enrollment [specific device model] (if function is not automatically implemented during MDM server install).'
  desc 'Good configuration management of a mobile device is a key capability for maintaining the mobile device’s security baseline. Restricting network access to only authorized devices is a key configuration management attribute. Device type is a key way to specify mobile devices that can be adequately secured.

SFR ID: FMT_SMF.1.1(2) b,
FIA_ENR_EXT.1.2'
  desc 'check', 'Review the BlackBerry UEM 12.8 server documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 

On the BlackBerry UEM 12.8, do the following:
1. Log in to the BlackBerry UEM 12.8 console and select the "Policies and profiles” tab on the left pane.
2. Expand the Activation profiles from the menu in the left pane.
3. Select the Activation Profile to be reviewed.
4. Select the "Settings" tab.
5. Select each supported operating system tab and perform the following:
6. Confirm that "Allow selected device models" is selected in the "Device model restrictions" field.
7. Verify that the devices listed in the "Allowed device models" field match the list provided by the administrator.

If the "Allow selected device models" is not displayed in the "Device model restrictions" field or the devices listed in the "Allowed device models" field do not match the list provided by the administrator, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM 12.8, do the following:

1. Log in to the BlackBerry UEM 12.8 console and select the "Policies and profiles” tab on the left pane.
2. Expand the Activation profiles from the menu in the left pane.
3. Select the Activation profile to be modified.
4. Select the "pencil" icon to edit the profile.
5. Select the "Settings" tab.
6. Select each supported operating system tab.
7. Select "Allow selected device models" in the "Device model restrictions" field, using the drop-down menu.
8. Select the edit button in the "Allowed device models" field.
9. Using the popup menu, select the required model and press the "->"arrow icon to add the selection to the "selected" window.
10. Once all models are selected, click "Save".
11. Click "Save".'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Manager (UEM) 12.8'
  tag check_id: 'C-80745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81057'
  tag rid: 'SV-95769r1_rule'
  tag stig_id: 'BUEM-12-807300'
  tag gtitle: 'PP-MDM-311046'
  tag fix_id: 'F-87863r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
