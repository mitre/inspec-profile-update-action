control 'SV-213332' do
  title 'The McAfee Application Control Options Advanced Threat Defense (ATD) settings must not be enabled unless an internal ATD is maintained by the organization.'
  desc 'This option will automatically send files with a specific file reputation to ATD for further analysis. This option is not selected by default and must only be selected if an ATD is being used.'
  desc 'check', 'If an ATD server is not being used in the environment, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset(s) that need the organization-specific policy.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

Verify the option for sending binaries for analysis under the "Advanced Threat Defense (ATD) settings" is selected.

Consult with the ISSO/ISSM to review the written policy to verify the usage of an ATD is documented.

If the option for sending binaries for analysis under the "Advanced Threat Defense (ATD) settings" is selected and the written policy does not include documentation on the usage of an ATD, this is a finding.'
  desc 'fix', 'If an ATD server is not being used in the environment, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

Place a check in the "Advanced Threat Defense (ATD) settings: Send binaries" check box.

Click "Save".

Update the written policy to ensure the usage of an ATD is documented.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14560r505031_chk'
  tag severity: 'medium'
  tag gid: 'V-213332'
  tag rid: 'SV-213332r506897_rule'
  tag stig_id: 'MCAC-TE-000106'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-14558r505032_fix'
  tag 'documentable'
  tag legacy: ['SV-88899', 'V-74225']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
