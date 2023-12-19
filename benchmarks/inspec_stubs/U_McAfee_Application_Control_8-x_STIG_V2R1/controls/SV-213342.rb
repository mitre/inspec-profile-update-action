control 'SV-213342' do
  title 'The McAfee Applications Default Rules policy must be part of the effective rules policy applied to every endpoint.'
  desc 'To ensure Solidcore clients are only configured to STIG and organization-specific settings, organization-specific ePO policies must be applied to all organization workstation endpoints.

The McAfee Application Control installs with two Default Rules policies.

The McAfee Default Rules policy includes the whitelist for commonly used applications to the platform.

The McAfee Applications Default Rules policy include the whitelist for McAfee applications.

Both of these policies are at the "My Organization" level of the System Tree and must be inherited by all branches of the System Tree.

Organization-specific applications would be whitelisted with an organization-specific policy combined with the two Default policies into one effective policy.'
  desc 'check', 'This requirement is only applicable to Windows platforms. For MAC and Linux platforms, this is Not Applicable.

From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".

Select the asset to be validated.

Select "Actions".

Select "Agent".

Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

For the "Application Control Rules (Windows)" Category, click on "Edit Assignments" under the "Actions" column.

Verify that the McAfee Applications Default Rules policy is part of the assigned policies applied to the system being reviewed.

If the McAfee Applications Default Rules policy is not part of the assigned polices applied to the system being reviewed, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the "Systems" tab.

Select "This Group and All Subgroups".
Select the asset.
Select "Actions".
Select "Agent".
Select "Modify Policies on a Single System".

From the product pull-down list, select Solidcore 8.x: Application Control.

For the "Application Control Rules (Windows)" Category, click on "Edit Assignments" under the "Actions" column.

Click on the "New Policy Instance" button at the bottom of the screen.

Scroll down to locate the new policy instance just created.

Click on the drop-down selection box for "Assigned policy:" and choose "McAfee Applications (McAfee Default)".

Select the "Locked (prevent breaking inheritance below this point)" radio button.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14570r505061_chk'
  tag severity: 'medium'
  tag gid: 'V-213342'
  tag rid: 'SV-213342r506897_rule'
  tag stig_id: 'MCAC-TE-000117'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-14568r505062_fix'
  tag 'documentable'
  tag legacy: ['SV-88921', 'V-74247']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
