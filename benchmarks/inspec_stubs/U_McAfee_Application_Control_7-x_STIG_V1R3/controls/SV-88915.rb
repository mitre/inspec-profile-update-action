control 'SV-88915' do
  title 'The McAfee Application Control Options Inventory option must be configured to hide OS Files.'
  desc '<0> [object Object]'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Inventory" tab, review options selected.

If the "Hide Windows OS Files: Inventory items signed with Microsoft certificates will not be sent to McAfee ePO." option is not selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control. 

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Inventory" tab, place a check in the "Inventory: Hide Windows OS Files: Inventory items signed with Microsoft certificates will not be sent to McAfee ePO." check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74241'
  tag rid: 'SV-88915r1_rule'
  tag stig_id: 'MCAC-TE-000114'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80783r2_fix'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
