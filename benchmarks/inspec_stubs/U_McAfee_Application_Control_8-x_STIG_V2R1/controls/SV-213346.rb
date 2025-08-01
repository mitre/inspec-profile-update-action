control 'SV-213346' do
  title 'The Throttling settings must be enabled and configured to settings according to organizations requirements.'
  desc 'The throttling settings regulate the data flow between the clients and McAfee ePO. The value for each category defines the number of entries that will be sent to the McAfee ePO daily. Clients start caching for the defined category when the specified threshold value is reached. After the cache is full, new data for that category is dropped and not sent to the McAfee ePO. As such, settings must be high enough to allow for all data to reach the McAfee ePO.'
  desc 'check', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: General.

From the "Policy" column, select the policy associated with the Category "Configuration (Client)" that is specific to the organization and select the "Throttling" tab.

Verify the "Enable Throttling" check box is selected.

Verify the throttling settings are configured according to organization's written policy.

If the "Enable Throttling" check box is not selected, this is a finding.

If the throttling settings do not match the organization's written policy or the settings are not documented in the written policy, this is a finding.)
  desc 'fix', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: General.

From the "Policy" column, select the policy associated with the Category "Configuration (Client)" that is specific to the organization and select the "Throttling" tab.

Place a check in the "Enable Throttling" check box.

Configure the throttling settings based upon organization's written policy.

Click "Save".)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14574r505073_chk'
  tag severity: 'medium'
  tag gid: 'V-213346'
  tag rid: 'SV-213346r506897_rule'
  tag stig_id: 'MCAC-TE-000121'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14572r505074_fix'
  tag 'documentable'
  tag legacy: ['V-74255', 'SV-88929']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
