control 'SV-254883' do
  title 'Documentation identifying Tanium console users, their respective User Groups, Computer Groups, and Roles must be maintained.'
  desc 'System access must be reviewed periodically to verify all Tanium users are assigned the appropriate functional role, with the least privileged access possible to perform assigned tasks being the recommended best practice to avoid unauthorized access.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of Tanium users. User Groups, Roles, Computer Groups, and correlated LDAP security groups must be documented for users.

If the documentation does not exist, or is missing any Tanium users and their respective User Groups, Roles, Computer Groups, and correlated LDAP security groups documentation, this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58496r867547_chk'
  tag severity: 'medium'
  tag gid: 'V-254883'
  tag rid: 'SV-254883r867549_rule'
  tag stig_id: 'TANS-AP-000105'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-58440r867548_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
