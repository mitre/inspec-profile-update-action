control 'SV-213334' do
  title 'The McAfee Application Control Options Advanced Threat Defense (ATD) settings, if being used, must be configured to only send binaries with a size of 5 MB or less.'
  desc 'Since binaries can be large, the file size must be limited to avoid congestion on the network and degradation on the endpoint when sending the binaries to the ATD.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

If an ATD server is not being used in the environment, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

Select the "Reputation" tab.

If the option for sending binaries for analysis under the "Advanced Threat Defense (ATD) settings" is selected, verify the "Limit file size to" option is set to 5 MB or less.

If the "Limit file size to" option is not set to 5 MB or less, this is a finding.'
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

In the drop-down selection box of the "Advanced Threat Defense (ATD) settings: Limit file save" text box, enter a value of 5 MB or less.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14562r505037_chk'
  tag severity: 'medium'
  tag gid: 'V-213334'
  tag rid: 'SV-213334r506897_rule'
  tag stig_id: 'MCAC-TE-000108'
  tag gtitle: 'SRG-APP-000276'
  tag fix_id: 'F-14560r505038_fix'
  tag 'documentable'
  tag legacy: ['SV-88903', 'V-74229']
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
