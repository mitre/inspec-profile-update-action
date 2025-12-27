control 'SV-88907' do
  title 'The McAfee Application Control Options policy must be configured to disable Self-Approval.'
  desc 'The McAfee Application Control Self-Approval feature allows the user to take an action when a user tries to run a new or unknown application.'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Self-Approval" tab, verify the "Enable Self-Approval" check box is not selected.

If the "Enable Self-Approval" check box is selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Self-Approval" tab, de-select the "Enable Self-Approval" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74269r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74233'
  tag rid: 'SV-88907r1_rule'
  tag stig_id: 'MCAC-TE-000110'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80775r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
