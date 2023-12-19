control 'SV-213345' do
  title 'The organization-specific Solidcore Client Policies must be created and applied to all endpoints.'
  desc 'McAfee Application Control is deployed with default policies. To ensure the default policies are not used and that an organization knowingly configures their systems to their own configuration requirements, organization-specific policies will need to be created.'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: General.

From the "Policy" column, select the policy associated with the Category "Configuration (Client)" that is specific to the organization.

If the only "Configuration (Client)" policy applied to the system is the "McAfee Default" policy, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: General.

From the "Actions" column, select "Edit Assignment" for the "Solidcore (Client)" Category.

Next to "Assigned policy:", click on the drop-down selection box and choose an organization-specific "Solidcore (Client)" policy.

Click "Save".

If no organization-specific Solidcore (Client) policy exists, click on "New Policy". Choose "McAfee Default" for "Create a policy based on this existing policy".

Type a unique Policy Name.

Click "OK".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14573r505070_chk'
  tag severity: 'medium'
  tag gid: 'V-213345'
  tag rid: 'SV-213345r506897_rule'
  tag stig_id: 'MCAC-TE-000120'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14571r505071_fix'
  tag 'documentable'
  tag legacy: ['SV-88927', 'V-74253']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
