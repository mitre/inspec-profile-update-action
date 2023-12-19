control 'SV-88925' do
  title 'The organization-specific Rules policies must be part of the effective rules policy applied to all endpoints.'
  desc 'To ensure Solidcore clients are only configured to STIG and organization-specific settings, an organization-specific ePO policies must be applied to all organization workstation endpoints.

The McAfee Application Control installs with two Default Rules policies. 

The McAfee Default Rules policy includes the whitelist for commonly used applications to the platform.

The McAfee Applications Default Rules policy include the whitelist for McAfee applications.

Both of these policies are at the "My Organization" level of the System Tree and must be inherited by all branches of the System Tree.

Organization-specific applications would be whitelisted with an organization-specific policy combined with the two Default policies into one effective policy.'
  desc 'check', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

For the "Application Control Rules (Windows)" Category, click on "Edit Assignments" under the "Actions" column.

Verify that there exists at least one organization-specific Rules policy as part of the assigned policies applied to the system being reviewed.

If an organization-specific Rules policy is not part of the assigned polices applied to the system being reviewed, this is a finding.

If the only "Application Control Rules" policy applied to the system is the "McAfee Default" policy, this is a finding.'
  desc 'fix', %q(From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups". 
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 7.x: Application Control.

For the "Application Control Rules (Windows)" Category, click on "Edit Assignments" under the "Actions" column.

Click on the "New Policy Instance" button at the bottom of the screen.

Scroll down to locate the new policy instance just created. Click on the drop-down selection box for "Assigned policy:" and choose the organization-specific policy for the system being reviewed.

If one does not exist, click "New Policy" and create a new policy based upon organization's written policy.

Click "Save".)
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74251'
  tag rid: 'SV-88925r1_rule'
  tag stig_id: 'MCAC-TE-000119'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-80793r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
