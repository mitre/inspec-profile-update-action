control 'SV-108131' do
  title 'The BlackBerry UEM 12.11 server must be capable of performing the following management function: configure the [selection: devices specified by [selection: specific device models]].'
  desc 'Access control of mobile devices to DoD sensitive information or access to DoD networks must be controlled so that DoD data will not be compromised. The primary method of access control of mobile devices is via enrollment of authorized mobile devices on the BlackBerry UEM 12.11 server. Therefore, the BlackBerry UEM 12.11 server must have the capability to enforce a policy for this control.

SFR ID: FMT_SMF.1.1(2) b, FIA_ENR_EXT.1.2'
  desc 'check', 'Review the BlackBerry UEM 12.11 server documentation and configuration settings to determine if the warning banner is using the appropriate designated wording. 

On the BlackBerry UEM 12.11, do the following:
1. Log in to the BlackBerry UEM 12.11 console.
2. Select the "Policies and profiles" tab on the left pane.
3. Expand the Activation profiles from the menu in the left pane.
4. Select the Activation Profile to be reviewed.
5. Select the "Settings" tab. Select each supported operating system tab and perform the following:
- Confirm that "Allow selected device models" is selected in the "Device model restrictions" field.
- Verify that the devices listed in the "Allowed device models" field match the list provided by the administrator.

If the "Allow selected device models" is not displayed in the "Device model restrictions" field or the devices listed in the "Allowed device models" field do not match the list provided by the administrator, this is a finding.'
  desc 'fix', 'On the BlackBerry UEM 12.11, do the following:

1. Log in to the BlackBerry UEM 12.11 console.
2. Select the "Policies and profiles" tab on the left pane.
3. Under the "Policy" dropdown, select "Activation".
4. Select the Activation profile to be modified.
5. Select the pencil icon to edit the profile.
6. Select the "Settings" tab.
7. Select each supported operating system tab.
8. In the "Device model restrictions" field, use the drop-down menu to elect "Allow selected device models".
9. Select the "edit" button in the "Allowed device models" field.
10. Using the pop-up menu, select the allowed model(s) and press the "->" arrow icon to add the selection to the "selected" window.
11. Once all models are selected, click "Save".
12. Repeat as applicable for other operating systems.
13. Click "Save".'
  impact 0.5
  ref 'DPMS Target BlackBerry Unified Endpoint Manager (UEM) 12.11'
  tag check_id: 'C-97867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99027'
  tag rid: 'SV-108131r1_rule'
  tag stig_id: 'BUEM-12-110520'
  tag gtitle: 'PP-MDM-412046'
  tag fix_id: 'F-104703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
