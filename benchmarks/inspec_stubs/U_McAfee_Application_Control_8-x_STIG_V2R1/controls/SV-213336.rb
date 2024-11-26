control 'SV-213336' do
  title 'The McAfee Application Control Options policy must be configured to disable Self-Approval.'
  desc 'The McAfee Application Control Self-Approval feature allows the user to take an action when a user tries to run a new or unknown application.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Self-Approval" tab, verify the "Enable Self-Approval" check box is not selected.

If the "Enable Self-Approval" check box is selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Self-Approval" tab, de-select the "Enable Self-Approval" check box.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14564r505043_chk'
  tag severity: 'medium'
  tag gid: 'V-213336'
  tag rid: 'SV-213336r506897_rule'
  tag stig_id: 'MCAC-TE-000110'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14562r505044_fix'
  tag 'documentable'
  tag legacy: ['SV-88907', 'V-74233']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
