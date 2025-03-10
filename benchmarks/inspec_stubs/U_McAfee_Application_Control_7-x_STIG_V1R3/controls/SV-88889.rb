control 'SV-88889' do
  title 'The organization-specific Rules policy must only include executable and dll files that are associated with applications as allowed by the organizations written policy.'
  desc 'To ensure Solidcore clients are only configured to STIG and organization-specific settings, organization-specific ePO policies must be applied to all organization workstation endpoints.

The McAfee Application Control installs with two Default Rules policies.

The McAfee Default Rules policy includes the whitelist for commonly used applications to the platform.

The McAfee Applications Default Rules policy include the whitelist for McAfee applications.

Both of these policies are at the "My Organization" level of the System Tree and must be inherited by all branches of the System Tree.

Organization-specific applications would be whitelisted with an organization-specific policy combined with the two Default policies into one effective policy.'
  desc 'check', %q(Obtain the organization's written policy for the McAfee Application Control software from the System or ePO Administrator.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select "Solidcore 7.x: Application Control".

For the "Application Control Rules (Windows)" Category, click on "Edit Assignments" under the "Actions" column.

Identify the organization-specific Rules policy applied to the system being reviewed.

Click on "Edit Policy" beside the organization-specific Rules policy.

Verify the list of applications under each of the "Rules Groups" in the organization-specific Rules policy against the written policy's list of allowed applications.

If the organization-specific Rules policy contains any applications not documented in the written policy as allowed, this is a finding.)
  desc 'fix', %q(Obtain the organization's written policy for the McAfee Application Control software from the System or ePO Administrator.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

Remove any "Rules Groups" and/or applications under the "Rules Groups" that do not comply with the organization's written policy.

If applications are required, follow the formal change and acceptance process to document the applications in the organization's written policy.)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74215'
  tag rid: 'SV-88889r1_rule'
  tag stig_id: 'MCAC-TE-000103'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80757r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
