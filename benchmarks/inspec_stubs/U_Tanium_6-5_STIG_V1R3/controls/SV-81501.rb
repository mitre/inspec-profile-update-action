control 'SV-81501' do
  title 'Tanium console users Computer Group rights must be validated against the documentation for Computer Group rights.'
  desc 'System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Users" tab. 

Verify each user against the provided list, and review the assigned group rights for each user against the "Group Rights" column.

If any user exists in Tanium but is not on the documented list and/or if any user exists in Tanium with more Group Rights than documented on the list, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Users" tab.

For any user(s) in Tanium which is not on the approved, documented list, access the Microsoft Windows Active Directory Management and remove the respective user(s) from the AD Security Group in which those user(s) are members.

For any user in Tanium which has not been assigned one or more Computer Groups as has been documented in the Computer Groups list, access the Microsoft Windows Active Directory Management and add the respective user(s) to the AD Security Groups applicable for the roles for which the user(s) have been documented to be authorized.

Click “Save”.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67011'
  tag rid: 'SV-81501r1_rule'
  tag stig_id: 'TANS-CN-000009'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-73111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
