control 'SV-234051' do
  title 'Documentation identifying Tanium console users, their respective functional roles, and computer groups must be maintained.'
  desc "System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate functional role, with the least privileged access possible to perform assigned tasks being the recommended best practice. Users who have been removed from the documentation should no longer be configured as a Tanium Console User. Consider removing users that have not logged onto the system within a predetermined time frame.

When using Active Directory synchronization, as is required by this STIG, User Roles assignments are via the LDAP Sync.

To change a Tanium user's functional role, their Active Directory account needs to be assigned to the AD security group, which correlates with the applicable functional role."
  desc 'check', "Consult with the Tanium System Administrator to review the documented list of Tanium users. The users' functional roles, computer groups, and correlated Active Directory security groups must be documented.

If the site does not have the Tanium users and their respective functional roles, computer groups, and correlated Active Directory security groups documented, this is a finding."
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective User Roles and AD security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37236r610653_chk'
  tag severity: 'medium'
  tag gid: 'V-234051'
  tag rid: 'SV-234051r612749_rule'
  tag stig_id: 'TANS-CN-000005'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37201r610654_fix'
  tag 'documentable'
  tag legacy: ['SV-102175', 'V-92073']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
