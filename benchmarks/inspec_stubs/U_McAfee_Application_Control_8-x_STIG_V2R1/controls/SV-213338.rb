control 'SV-213338' do
  title 'The McAfee Application Control Options policies Enforce feature control memory protection must be enabled.'
  desc 'By default, the McAfee Application Control prevents installation of ActiveX controls on endpoints, enforces memory protection techniques on endpoints, and prevents MSI-installers from running on endpoints. The Feature Control allows for those safeguards to be bypassed and in doing so renders the McAfee Application Control less effective.

Because ENS and HIPs have many more types of memory protection techniques than McAfee Application Control, memory protection must be explicitly disabled.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset(s) that need the organization-specific policy.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Features" tab, review options selected.

If the "Enforce feature control" check box is not selected and/or "Memory protection" is selected, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Features" tab, place a check in the "Enforce feature control" check box.

Remove the check in the "Memory protection" check box.

Select or de-select remaining features, based upon written policy.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14566r505049_chk'
  tag severity: 'medium'
  tag gid: 'V-213338'
  tag rid: 'SV-213338r561345_rule'
  tag stig_id: 'MCAC-TE-000112'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14564r505050_fix'
  tag 'documentable'
  tag legacy: ['SV-88911', 'V-74237']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
