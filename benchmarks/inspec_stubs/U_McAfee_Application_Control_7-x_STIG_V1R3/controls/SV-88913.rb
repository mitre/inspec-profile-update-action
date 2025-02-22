control 'SV-88913' do
  title 'Enabled features under McAfee Application Control Options policies Enforce feature control must not be configured unless documented in written policy and approved by ISSO/ISSM.'
  desc 'By default, the McAfee Application Control prevents installation of ActiveX controls on endpoints, enforces memory protection techniques on endpoints, and prevents MSI-installers from running on endpoints. The "Feature Control" allows for those safeguards to be bypassed and in doing so renders the McAfee Application Control less effective.'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control. From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Features" tab, review options selected.

If the "Enforce feature control" check box is selected with any features, consult with the ISSO/ISSM to review the written policy and ensure the usage of additional features are documented.

If the usage of additional features are not documented in the written policy, this is a finding.'
  desc 'fix', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control. From the "Policy" column, select the policy associated with the Category "Application Control Options (Windows)".

On the "Features" tab, remove any features selected.

If features are required technically that are not documented in the organization's written policy, document the use of those features following the formal change and acceptance process as documented in the organization's written policy.)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74239'
  tag rid: 'SV-88913r1_rule'
  tag stig_id: 'MCAC-TE-000113'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80781r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
