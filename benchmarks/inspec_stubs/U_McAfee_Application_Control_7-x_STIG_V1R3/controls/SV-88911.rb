control 'SV-88911' do
  title 'The McAfee Application Control Options policies Enforce feature control memory protection must be enabled.'
  desc 'By default, the McAfee Application Control prevents installation of ActiveX controls on endpoints, enforces memory protection techniques on endpoints, and prevents MSI-installers from running on endpoints. The Feature Control allows for those safeguards to be bypassed and in doing so renders the McAfee Application Control less effective.'
  desc 'check', 'If HIPS/ENS is enabled and enforced, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Features" tab, review options selected.

If the "Enforce feature control" check box is not selected and "Memory protection" is selected, this is a finding.'
  desc 'fix', 'If HIPS/ENS is enabled and enforced, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Features" tab, place a check in the "Enforce feature control" check box.

Place a check in the "Memory protection" check box.

Select or de-select remaining features, based upon written policy.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74237'
  tag rid: 'SV-88911r1_rule'
  tag stig_id: 'MCAC-TE-000112'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80779r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
