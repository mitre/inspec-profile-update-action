control 'SV-213335' do
  title 'Organization-specific McAfee Applications Control Options policies must be created and applied to all endpoints.'
  desc 'To ensure Solidcore clients are only configured to STIG and organization-specific settings, organization-specific ePO policies must be applied to all organization workstation endpoints rather than resorting to the McAfee Applications Control (Default) policy.'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)" that is specific for the asset being reviewed.

If the only "Application Control Options" policy applied to the system is the "McAfee Default" policy, this is a finding.'
  desc 'fix', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Actions" column, select "Edit Assignment" for the "Application Control Options (Windows) Category".

Next to "Assigned policy:", click on drop-down selection box and choose an organization-specific Application Control Options policy for the asset being reviewed.

Click "Save".

If no organization-specific Application Control Options policy exist, click on "New Policy".

Choose "McAfee Default" for "Create a policy based on this existing policy".

Type a unique Policy Name.

Click "OK".

Configure the "Self-Approval", "End User Notifications", "Features", "Inventory", and "Reputation" tabs according to the organization's written policy and remaining STIG settings.)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14563r505040_chk'
  tag severity: 'medium'
  tag gid: 'V-213335'
  tag rid: 'SV-213335r506897_rule'
  tag stig_id: 'MCAC-TE-000109'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14561r505041_fix'
  tag 'documentable'
  tag legacy: ['SV-88905', 'V-74231']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
