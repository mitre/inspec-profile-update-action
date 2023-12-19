control 'SV-253818' do
  title 'Documentation identifying Tanium console users, their respective User Groups, Computer Groups, and Roles must be maintained.'
  desc 'System access should be reviewed periodically to verify that all Tanium users are assigned the appropriate functional role, with the least privileged access possible to perform assigned tasks being the recommended best practice to avoid unauthorized access.'
  desc 'check', "Consult with the Tanium system administrator to review the documented list of Tanium users. The users' User Groups, Roles, Computer Groups, and correlated LDAP security groups must be documented.

If the documentation does not exist or is missing any Tanium users and their respective User Groups, Roles, Computer Groups, and correlated LDAP security groups, this is a finding."
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57270r842480_chk'
  tag severity: 'medium'
  tag gid: 'V-253818'
  tag rid: 'SV-253818r842482_rule'
  tag stig_id: 'TANS-CN-000005'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-57221r842481_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
