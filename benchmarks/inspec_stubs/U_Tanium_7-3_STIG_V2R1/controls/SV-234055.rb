control 'SV-234055' do
  title 'Tanium console users Computer Group rights must be validated against the documentation for Computer Group rights.'
  desc 'System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Users" tab.

Verify each user against the approved users list.

Review the assigned Computer Groups for each user by selecting the user then clicking view user.

View Computer Groups for the user.

If any user exists in Tanium but is not on the Tanium-approved users list and/or if any user exists in Tanium with more Computer Groups than documented, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Users" tab.

For any user(s) in Tanium, which is not on the approved, documented Tanium user list, access Microsoft Windows Active Directory Management.

Remove, the respective user(s) from the AD Security Group in which those user(s) are members.

For any user in Tanium which has not been assigned one or more Computer Groups as has been documented in the Computer Groups list, access the Microsoft Windows Active Directory Management.

Add the respective user(s) to the AD Security Groups applicable for the functional roles for which the user(s) have been documented to be authorized.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37240r610665_chk'
  tag severity: 'medium'
  tag gid: 'V-234055'
  tag rid: 'SV-234055r612749_rule'
  tag stig_id: 'TANS-CN-000009'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37205r610666_fix'
  tag 'documentable'
  tag legacy: ['SV-102183', 'V-92081']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
