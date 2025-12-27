control 'SV-81493' do
  title 'Documentation identifying Tanium console users and their respective User Roles must be maintained.'
  desc "System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.

When using Active Directory synchronization, as is required by this STIG, User Roles assignments are via the AD Sync connector. AD security groups correlate, one to one, to Tanium User Roles.

To change a Tanium user's User Role, their Active Directory account needs to be moved to the AD security group which correlates with the applicable User Role."
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users. The users' respective, approved roles, as well as the correlated Active Directory security group for the User Roles, must be documented.

If the site does not have the Tanium users and their respective, approved roles and AD security groups documented, this is a finding."
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective User Roles and AD security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67003'
  tag rid: 'SV-81493r1_rule'
  tag stig_id: 'TANS-CN-000005'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-73103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
