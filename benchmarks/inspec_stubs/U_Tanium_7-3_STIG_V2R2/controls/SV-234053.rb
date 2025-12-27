control 'SV-234053' do
  title 'Tanium console users User Roles must be validated against the documentation for User Roles.'
  desc "System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.

When using Active Directory synchronization, as is required by this STIG, User Roles assignments are via the LDAP Sync, AD security groups correlate, one to one, to Tanium User Roles.

To change a Tanium user's User Role, their Active Directory account needs to be moved to the AD security group, which correlates with the applicable User Role."
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Users" tab.

Verify each user against the Tanium-approved users list.

Review the assigned roles for each user against the "User Functional Role" column.

If any user exists in Tanium but is not on the Tanium-approved users list and/or if any user exists in Tanium at a more elevated User Functional Role than that documented on the list, this is a finding.'
  desc 'fix', "When using Active Directory synchronization, as is required by this STIG, User Roles assignments are assigned by LDAP sync. AD security groups correlate, one to one, to Tanium User Roles.

To change a Tanium user's User Functional Role, their Active Directory account needs to be moved to the AD security group, which correlates with the applicable User Functional Role.

Access the Active Directory server.

Locate the account(s), which have been determined to have the incorrect User Functional Roles in Tanium.

Review the Tanium-related AD Security Groups to which the user account(s) belong that directly correlate to the incorrect Tanium User Functional Roles.

Remove the user account(s) from the incorrect Tanium User Roles, ensuring the user account(s) are still members of the Tanium-related AD Security Groups for which they have been documented to be authorized."
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37238r610659_chk'
  tag severity: 'medium'
  tag gid: 'V-234053'
  tag rid: 'SV-234053r612749_rule'
  tag stig_id: 'TANS-CN-000007'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37203r610660_fix'
  tag 'documentable'
  tag legacy: ['SV-102179', 'V-92077']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
